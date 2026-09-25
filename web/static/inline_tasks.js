"use strict";

// Progressive enhancement for explicitly allowlisted preview-only forms.
// Credentials stay in the original DOM, never browser storage or task UI.
(() => {
  const modal = document.querySelector("[data-inline-task-modal]");
  if (!modal) return;
  const part = name => modal.querySelector(`[data-inline-${name}]`);
  const flows = new Map();
  const drafts = new WeakSet();
  const proxyOperations = new Set(["airport_add", "airport_update", "airport_delete", "exit_add", "exit_update", "exit_delete", "exit_set_default"]);
  let active = null;

  function safeUrl(raw) {
    const url = new URL(raw, window.location.href);
    if (url.origin !== window.location.origin) throw new Error("响应地址无效，未继续操作。");
    return url;
  }

  function config(form) {
    if (form.method.toLowerCase() !== "post") return null;
    const path = safeUrl(form.getAttribute("action") || window.location.pathname).pathname;
    const field = name => form.querySelector(`[name="${name}"]`)?.value || "";
    if (path === "/network/nodes/exits/preview/") return {key: `exits:${field("name")}`, region: form.closest(".node-exit-card")};
    if (path === "/network/permissions/preview/" && field("operation") === "deny") return {key: `permissions:${field("client")}`, region: form.closest(".permission-list")};
    if (path === "/network/nodes/domains/preview/") return {key: `domains:${field("name")}`, region: form.closest("article"), collection: ".global-host-records:not(.custom-host-records)"};
    if (path === "/network/addresses/domains/preview/") return {key: `address:${field("address")}`, region: form.closest("article"), collection: ".custom-host-records"};
    if (path === "/network/proxy/" && proxyOperations.has(field("operation"))) {
      const airport = field("operation").startsWith("airport_");
      return {key: `${airport ? "airport" : "exit"}:${field(airport ? "airport_id" : "exit_id")}`,
        region: form.closest(".airport-card"), collection: `${airport ? "#airport-resources" : "#exit-resources"} .airport-list`};
    }
    return null;
  }

  function regions(scope) {
    const found = new Map();
    scope.querySelectorAll("form").forEach(form => {
      const item = config(form);
      if (item?.region) found.set(item.key, item);
    });
    scope.querySelectorAll("[data-permission-client]").forEach(region => {
      const key = `permissions:${region.dataset.permissionClient}`;
      found.set(key, {key, region});
    });
    scope.querySelectorAll("[data-inline-key]").forEach(region => {
      const key = region.dataset.inlineKey;
      const collections = {airport: "#airport-resources .airport-list", exit: "#exit-resources .airport-list", address: ".custom-host-records", domains: ".global-host-records:not(.custom-host-records)"};
      found.set(key, {key, region, collection: collections[key.split(":")[0]]});
    });
    return found;
  }

  function lock(flow, locked) {
    if (locked && !flow.disabled) {
      flow.disabled = [...flow.form.elements].map(field => [field, field.disabled]);
      flow.disabled.forEach(([field]) => { field.disabled = true; });
    } else if (!locked && flow.disabled) {
      flow.disabled.forEach(([field, disabled]) => { field.disabled = disabled; });
      flow.disabled = null;
    }
    flow.form.setAttribute("aria-busy", String(locked));
    if (!locked) document.dispatchEvent(new CustomEvent("server-kit:form-unlocked", {detail: {form: flow.form}}));
  }

  function render(flow) {
    flow.badge.textContent = flow.message || "查看任务进度";
    if (active !== flow || modal.hidden) return;
    part("stage").textContent = flow.phase === "review" ? "统一确认 · 尚未应用" : "当前操作";
    modal.querySelector("h2").textContent = flow.task?.preview?.title || "核验变更";
    part("summary").textContent = flow.task?.preview?.summary || "填写内容保留在原页面。";
    part("status").textContent = flow.message || "";
    part("error").textContent = flow.error || "";
    part("error").hidden = !flow.error;
    const facts = part("facts");
    facts.replaceChildren();
    if (flow.phase === "review") Object.entries(flow.task?.preview?.facts || {}).forEach(([key, value]) => {
      const entry = document.createElement("div");
      const label = document.createElement("dt");
      const detail = document.createElement("dd");
      label.textContent = key; detail.textContent = String(value);
      entry.append(label, detail); facts.append(entry);
    });
    part("edit").hidden = !["review", "error"].includes(flow.phase);
    part("confirm").hidden = flow.phase !== "review";
    part("retry").hidden = flow.phase !== "uncertain";
    part("refresh").hidden = flow.phase !== "refresh-error";
    part("done").hidden = flow.phase !== "done";
    part("task-link").hidden = !flow.task;
    if (flow.task) part("task-link").href = `/tasks/${flow.task.id}/`;
  }

  function show(flow) {
    active = flow;
    openManagedModal(modal, flow.badge);
    render(flow);
    modal.querySelector("h2").focus();
  }

  function release(flow, restoreFocus = true) {
    lock(flow, false);
    flows.delete(flow.form);
    flow.badge.remove();
    if (!restoreFocus) return;
    if (flow.form.isConnected) (flow.opener?.isConnected ? flow.opener : flow.form.querySelector("input,button"))?.focus();
    else (regions(document).get(flow.config.key)?.region.querySelector("summary,button,input") || document.querySelector("#main-content"))?.focus();
  }

  function close() {
    const flow = active;
    closeManagedModal(modal);
    active = null;
    // Cancel/return before execution keeps the entire original editor intact.
    if (flow && ["review", "error", "done"].includes(flow.phase)) release(flow);
  }

  async function request(url, body, json = false) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch(safeUrl(url), {method: body === undefined ? "GET" : "POST", credentials: "same-origin", cache: "no-store", signal: controller.signal,
        headers: {Accept: json ? "application/json" : "text/html", ...(json && body ? {"Content-Type": "application/json", "X-CSRFToken": body.csrf} : {})},
        ...(body === undefined ? {} : {body: json ? JSON.stringify({task_id: body.task_id}) : body})});
      if (json) {
        if (response.redirected) throw new Error("登录可能已失效，请在新标签页登录后重试；当前内容已保留。");
        let data;
        try { data = await response.json(); } catch (_) { throw new Error("未收到有效任务响应。请先核验原任务，不要重复提交。"); }
        if (!response.ok) throw new Error(data.error || "读取任务失败。");
        return data;
      }
      const text = await response.text();
      const doc = new DOMParser().parseFromString(text, "text/html");
      if (!response.ok || response.redirected) {
        if (new URL(response.url).pathname === "/login/") throw new Error("登录已失效，请在新标签页登录后重试；当前内容已保留。");
        const messages = [...doc.querySelectorAll('[role="alert"], .messages .alert')].map(item => item.textContent.trim()).filter(Boolean);
        throw new Error(messages.join("；") || (response.status < 500 && !text.includes("<html") ? text.slice(0, 300) : "请求未完成，填写内容已保留，请检查状态后重试。"));
      }
      return doc;
    } catch (error) {
      if (error.name === "AbortError" || error instanceof TypeError) throw new Error("连接中断或响应超时。填写内容已保留；若已确认，请先查询原任务状态。");
      throw error;
    } finally { window.clearTimeout(timer); }
  }

  function checkTask(task, id) {
    if (!task || !/^task-[0-9a-f]{32}$/.test(task.id) || (id && task.id !== id)) throw new Error("任务标识无效，未继续操作。");
    const terminal = ["succeeded", "failed", "invalidated", "cancelled", "expired", "interrupted", "confirmed", "rolled_back"];
    const states = [...terminal, "waiting_confirmation", "queued", "running", "waiting_rollback_confirmation"];
    if (!states.includes(task.state) || task.terminal !== terminal.includes(task.state)) throw new Error("任务状态无效，请查询原任务，未自动重试。");
    return task;
  }

  function dirtyRegion(region, source) {
    return [...region.querySelectorAll("form")].some(form => form !== source && (drafts.has(form) || flows.has(form)));
  }

  async function refresh(flow) {
    try {
      const doc = await request(window.location.href);
      if (!doc.querySelector("#main-content") || doc.querySelector(".content > .alert.danger")) throw new Error("最新列表读取失败，原列表未覆盖。");
      const ready = {"/network/nodes/": "nodes", "/network/subscriptions/": "domains", "/network/proxy/": "proxy"}[window.location.pathname];
      if (!ready || !doc.querySelector(`[data-inline-ready="${ready}"]`)) throw new Error("最新列表不完整，原列表未覆盖。请稍后重新读取。");
      const before = regions(document), after = regions(doc);
      let retained = false;
      before.forEach((item, key) => {
        const next = after.get(key);
        if (dirtyRegion(item.region, flow.form) || (item.region.contains(document.activeElement) && !item.region.contains(flow.form))) { retained = true; return; }
        if (next) {
          // Preserve expanded editors; the new server copy contains no secrets.
          const open = [...item.region.querySelectorAll("details")].map(detail => detail.open);
          if (next.region.tagName === "DETAILS") next.region.open = item.region.open;
          [...next.region.querySelectorAll("details")].forEach((detail, index) => { detail.open = Boolean(open[index]); });
          const permissionCard = item.region.closest(".node-permission-card");
          if (permissionCard) permissionCard.querySelector("[data-permission-count]").textContent = next.region.closest(".node-permission-card").querySelector("[data-permission-count]").textContent;
          item.region.replaceWith(next.region);
        } else if (item.region.contains(flow.form)) item.region.remove();
      });
      after.forEach((item, key) => {
        if (before.has(key) || !item.collection) return;
        const collection = document.querySelector(item.collection);
        if (!collection) return;
        [...collection.children].filter(child => child.matches(".empty-state, .privacy-note")).forEach(child => child.remove());
        collection.append(item.region);
      });
      for (const selector of ["#airport-resources .airport-list", "#exit-resources .airport-list", ".custom-host-records"]) {
        const collection = document.querySelector(selector), latest = doc.querySelector(selector);
        if (collection && latest && !collection.querySelector("[data-inline-key]") && !latest.querySelector("[data-inline-key]")) {
          collection.replaceChildren(...[...latest.children].filter(child => child.matches(".empty-state, .privacy-note")));
        }
      }
      const metrics = document.querySelector(".proxy-metrics");
      const nextMetrics = doc.querySelector(".proxy-metrics");
      if (metrics && nextMetrics) metrics.replaceWith(nextMetrics);
      for (const selector of [".page-header .stage-badge", "#airport-resources .section-heading .eyebrow", "#exit-resources .section-heading .eyebrow"]) {
        const current = document.querySelector(selector), latest = doc.querySelector(selector);
        if (current && latest) current.textContent = latest.textContent;
      }
      document.dispatchEvent(new CustomEvent("server-kit:content-updated"));
      flow.phase = "done";
      flow.message = retained ? "已保存。其他正在编辑的区域保持原样，未覆盖未提交内容。" : "已保存，当前列表已更新。";
      flow.error = "";
      if (!flow.config.region) {
        lock(flow, false);
        flow.form.reset();
        flow.form.querySelector('input[name="exit_input_mode"]:checked')?.dispatchEvent(new Event("change", {bubbles: true}));
      }
      drafts.delete(flow.form);
    } catch (error) {
      flow.phase = "refresh-error";
      flow.message = "任务已成功，但最新列表尚未读取。请勿重复提交。";
      flow.error = error.message;
    }
    render(flow);
  }

  async function poll(flow) {
    if (flow.polling) return;
    flow.polling = true;
    try {
      const data = await request(`/inline-tasks/${flow.task.id}/`, undefined, true);
      flow.task = checkTask(data.task, flow.task.id);
      flow.error = "";
      if (flow.task.state === "succeeded") {
        flow.form.querySelectorAll('input[type="password"],textarea[name="exit_proxy_yaml"],input[name="exit_field_username"],input[name="exit_proxy_base"]').forEach(input => { input.value = ""; });
        document.dispatchEvent(new CustomEvent("server-kit:exit-edit-saved", {detail: {form: flow.form}}));
        await refresh(flow);
      } else if (flow.task.state === "waiting_confirmation") {
        flow.phase = "review"; flow.message = "尚未提交。可核对后确认同一个任务，不会重复执行。";
      } else if (flow.task.terminal) {
        flow.phase = flow.task.error?.code === "permission_recovery_required" ? "recovery" : "error";
        flow.message = "任务未完成，填写内容已保留。";
        flow.error = flow.task.error?.message || flow.task.state_label;
      } else {
        flow.phase = "running"; flow.message = flow.task.progress?.message || "后台处理中…";
        flow.timer = window.setTimeout(() => poll(flow), 2500);
      }
    } catch (error) {
      flow.phase = "uncertain"; flow.message = "暂时无法确认状态，请先查询原任务。"; flow.error = error.message;
    } finally { flow.polling = false; render(flow); }
  }

  document.addEventListener("input", event => {
    const form = event.target.closest("form");
    if (form && config(form)) drafts.add(form);
  });
  document.addEventListener("change", event => {
    const form = event.target.closest("form");
    if (form && config(form)) drafts.add(form);
  });
  document.addEventListener("server-kit:form-discarded", event => {
    if (event.detail?.form && !flows.has(event.detail.form)) drafts.delete(event.detail.form);
  });
  document.addEventListener("submit", async event => {
    const form = event.target;
    const options = config(form);
    if (event.defaultPrevented || !options) return;
    event.preventDefault();
    if (flows.has(form)) { show(flows.get(form)); return; }
    const body = new FormData(form);
    if (event.submitter?.name) body.append(event.submitter.name, event.submitter.value);
    const flow = {form, config: options, opener: event.submitter, csrf: body.get("csrfmiddlewaretoken"), phase: "previewing", message: "正在核验变更，尚未执行…"};
    flow.badge = document.createElement("button");
    flow.badge.type = "button"; flow.badge.className = "inline-task-badge copy-button";
    flow.badge.addEventListener("click", () => show(flow));
    form.after(flow.badge);
    flows.set(form, flow); lock(flow, true); show(flow);
    try {
      const doc = await request(form.action, body);
      const preview = doc.querySelector("#inline-task-preview");
      if (!preview) throw new Error("未取得变更预览，未自动执行；填写内容已保留。");
      flow.task = checkTask(JSON.parse(preview.textContent));
      if (flow.task.state !== "waiting_confirmation") throw new Error("任务不是待确认状态，未自动执行。");
      flow.phase = "review"; flow.message = "请核对上方影响。确认后才会执行。";
    } catch (error) { flow.phase = "error"; flow.message = "无法生成预览，填写内容已保留。"; flow.error = error.message; }
    render(flow);
    if ((modal.hidden || active !== flow) && ["review", "error"].includes(flow.phase)) release(flow, false);
  });

  part("confirm").addEventListener("click", async () => {
    const flow = active;
    if (!flow || flow.phase !== "review") return;
    flow.phase = "confirming"; flow.message = "正在确认原任务…"; render(flow);
    try {
      const data = await request(modal.dataset.executeUrl, {task_id: flow.task.id, csrf: flow.csrf}, true);
      flow.task = checkTask(data.task, flow.task.id);
      await poll(flow);
    } catch (error) { flow.phase = "uncertain"; flow.error = error.message; flow.message = "确认结果未知，不会自动重复提交。"; render(flow); }
  });
  part("retry").addEventListener("click", () => { if (active) poll(active); });
  part("refresh").addEventListener("click", () => { if (active) refresh(active); });
  part("edit").addEventListener("click", close);
  part("done").addEventListener("click", close);
  modal.querySelectorAll("[data-inline-close]").forEach(button => button.addEventListener("click", close));
  document.addEventListener("keydown", event => { if (event.key === "Escape" && !modal.hidden) { event.preventDefault(); close(); } });
  window.addEventListener("beforeunload", event => {
    const dirty = [...document.querySelectorAll("form")].some(form => drafts.has(form));
    if (dirty || [...flows.values()].some(flow => flow.phase !== "done")) { event.preventDefault(); event.returnValue = ""; }
  });
})();
