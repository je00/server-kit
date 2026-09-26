(() => {
  "use strict";
  const root = document.querySelector("[data-telemetry-url]");
  if (!root) return;
  const url = new URL(root.dataset.telemetryUrl, location.href);
  if (url.origin !== location.origin) return;
  const states = {active: "有流量", recent: "近期握手", idle: "暂无活动", never: "尚未握手", disabled: "已禁用", pending: "待接入", unknown: "未知", unsupported: "未开启统计"};
  const statuses = new Set(["ok", "warming_up", "unavailable", "reset"]);
  const sources = new Set(["awg", "xray", "none"]);
  let packet = null, samples = new Map(), sampledAt = 0, receivedAt = 0;
  let generation = 0, controller = null, timer = null, expiry = null, failures = 0, stopped = false;
  const interval = 2000, staleAfter = 8000;
  function valid(value) {
    if (!value || value.schema_version !== 1 || typeof value.sampled_at !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value.sampled_at) ||
      !Number.isFinite(Date.parse(value.sampled_at)) || !Number.isInteger(value.sample_age_ms) || value.sample_age_ms < 0 || value.sample_age_ms > 86400000 ||
      value.refresh_ms !== interval || value.stale_after_ms !== staleAfter || !Array.isArray(value.nodes) || value.nodes.length > 4096) return false;
    const ids = new Set();
    return value.nodes.every(node => {
      if (!node || typeof node.id !== "string" || !/^(awg|vless):[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(node.id) || ids.has(node.id) ||
        !Object.hasOwn(states, node.state) || !statuses.has(node.rate_status) || !sources.has(node.source) ||
        !(node.last_seen_at === null || Number.isFinite(node.last_seen_at) && node.last_seen_at >= 0)) return false;
      ids.add(node.id);
      const rates = [node.upload_bps, node.download_bps];
      if (node.source === "awg" && !node.id.startsWith("awg:") || node.source === "xray" && !node.id.startsWith("vless:")) return false;
      return node.rate_status === "ok" ? node.source !== "none" && !["disabled", "pending", "unknown", "unsupported"].includes(node.state) &&
        rates.every(rate => Number.isFinite(rate) && rate >= 0 && rate <= 1e15) : rates.every(rate => rate === null);
    });
  }
  function rate(value, compact) {
    if (value === null || !Number.isFinite(value)) return "—";
    const units = compact ? ["B", "K", "M", "G", "T"] : ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"];
    let power = 0;
    while (value >= 1024 && power < units.length - 1) { value /= 1024; power += 1; }
    return `${value < 10 && power ? value.toFixed(1) : Math.round(value)}${compact ? "" : " "}${units[power]}`;
  }
  function stale() { return !packet || performance.now() - receivedAt >= staleAfter; }
  function summary(state, node) {
    if (state === "stale") return "数据已过期";
    if (!node) return packet ? "暂无数据" : "采样中";
    if (node.rate_status === "reset") return "重新采样";
    if (node.rate_status === "warming_up") return "采样中";
    return states[node.state];
  }
  function render() {
    const expired = stale();
    root.querySelectorAll("[data-telemetry-node]").forEach(container => {
      const node = samples.get(container.dataset.telemetryNode);
      const state = packet && expired ? "stale" : node?.state || "unknown";
      container.dataset.telemetryState = state;
      const usable = !expired && node?.rate_status === "ok";
      const label = summary(state, node), up = usable ? node.upload_bps : null, down = usable ? node.download_bps : null;
      const compact = container.dataset.telemetryCompact === "true";
      const shortLabel = compact ? ({"未开启统计": "未开启", "尚未握手": "未握手", "数据已过期": "已过期"}[label] || label) : label;
      for (const status of container.querySelectorAll("[data-telemetry-state-label]")) status.textContent = shortLabel;
      const text = `↑${rate(up, compact)} ↓${rate(down, compact)}`;
      if (container.dataset.telemetryBaseLabel) container.setAttribute("aria-label", `${container.dataset.telemetryBaseLabel} ${label}；节点发往 VPS ${rate(up, false)}，从 VPS 接收 ${rate(down, false)}。`);
      for (const rates of container.querySelectorAll("[data-telemetry-rates]")) {
        if (rates.textContent !== text) rates.textContent = text;
        rates.title = `${label}；节点 → VPS：${rate(up, false)}；VPS → 节点：${rate(down, false)}`;
        rates.setAttribute("aria-label", rates.title);
      }
      const note = container.querySelector("[data-telemetry-status]");
      if (note) {
        note.title = `${label}${node?.last_seen_at ? `；上次握手 ${new Date(node.last_seen_at * 1000).toLocaleString("zh-CN", {hour12: false})}` : ""}。近期握手不等于实时连通。`;
      }
    });
    const label = root.querySelector("[data-telemetry-update]");
    if (label) {
      const state = stopped || document.hidden ? "paused" : packet && expired ? "stale" : failures ? "retrying" : packet ? "ready" : "loading";
      label.dataset.state = state;
      label.textContent = {paused: "已暂停 · 返回页面自动更新", stale: "数据已过期 · 正在重试", retrying: "刷新暂不可用 · 正在重试", ready: "每 2 秒更新", loading: "正在采样…"}[state];
      if (packet) label.title = `最近采样 ${new Date(packet.sampled_at).toLocaleString("zh-CN", {hour12: false})}`;
    }
  }
  function armExpiry() {
    clearTimeout(expiry);
    if (packet && !stale() && !stopped && !document.hidden) expiry = setTimeout(render, Math.max(1, staleAfter - (performance.now() - receivedAt)));
  }
  function schedule(delay = interval) {
    clearTimeout(timer);
    if (!stopped && !document.hidden) timer = setTimeout(poll, delay);
  }
  async function poll() {
    if (controller || stopped || document.hidden) return;
    const active = new AbortController(), version = ++generation, requestedAt = performance.now();
    controller = active;
    const timeout = setTimeout(() => active.abort(), 5000);
    try {
      const response = await fetch(url.href, {method: "GET", credentials: "same-origin", cache: "no-store", headers: {Accept: "application/json"}, signal: active.signal});
      if (!response.ok || !response.headers.get("content-type")?.includes("application/json")) throw new Error("unavailable");
      const next = await response.json();
      if (version !== generation || active.signal.aborted) return;
      if (!valid(next) || Date.parse(next.sampled_at) < sampledAt) throw new Error("invalid-sample");
      const nextAt = Date.parse(next.sampled_at);
      // Age comes from the VPS, not the device's wall clock. Including the full
      // request duration is conservative: a delayed response cannot look new.
      const sampleReceivedAt = requestedAt - next.sample_age_ms;
      if (!packet || nextAt > sampledAt) {
        packet = next; sampledAt = nextAt; receivedAt = sampleReceivedAt;
        samples = new Map(next.nodes.map(node => [node.id, node]));
      } else {
        // A cached/repeated sample may get older, but must never renew its TTL.
        receivedAt = Math.min(receivedAt, sampleReceivedAt);
      }
      failures = 0;
      render(); armExpiry();
      root.dispatchEvent(new CustomEvent("node-telemetry-updated", {detail: {ids: [...samples.keys()]}}));
    } catch (_) {
      if (version !== generation) return;
      failures += 1; render(); armExpiry();
    } finally {
      clearTimeout(timeout);
      if (version === generation) { controller = null; schedule(failures ? Math.min(30000, interval * 2 ** Math.min(failures, 4)) : interval); }
    }
  }
  function pause() {
    generation += 1; controller?.abort(); controller = null;
    clearTimeout(timer); clearTimeout(expiry); render();
  }
  document.addEventListener("visibilitychange", () => { if (document.hidden) pause(); else { render(); armExpiry(); poll(); } });
  window.addEventListener("pagehide", () => { stopped = true; pause(); });
  window.addEventListener("pageshow", () => { stopped = false; render(); armExpiry(); poll(); });
  root.addEventListener("node-telemetry-bind", render);
  render(); poll();
})();
