(() => {
  "use strict";

  const root = document.querySelector("[data-topology-root]");
  const initial = document.getElementById("topology-data");
  if (!root || !initial) return;
  const graph = root.querySelector("[data-topology-graph]");
  const select = root.querySelector("[data-topology-select]");
  const form = root.querySelector("[data-topology-form]");
  const refresh = root.querySelector("[data-topology-refresh]");
  const search = root.querySelector("[data-topology-search]");
  const prev = root.querySelector("[data-topology-prev]");
  const next = root.querySelector("[data-topology-next]");
  const status = root.querySelector("[data-topology-status]");
  const details = root.querySelector("[data-topology-details]");
  const svgNS = "http://www.w3.org/2000/svg";
  const relationTypes = new Set(["mutual", "outbound", "inbound", "denied", "unknown", "not_applicable"]);
  const permissionTypes = new Set(["allowed", "partial", "denied", "inactive", "unknown", "not_applicable"]);
  const nodeKinds = new Set(["hub", "awg", "vless"]);
  const availabilityTypes = new Set(["hub", "enabled", "disabled", "pending", "unknown"]);
  const nodeStringKeys = ["id", "name", "kind", "kind_label", "address", "state", "availability", "online_label"];
  let snapshot;
  let page = 0;
  let controller = null;
  let generation = 0;
  let layoutFrame = null;
  let requestedId = null;

  function stringList(value) { return Array.isArray(value) && value.every(item => typeof item === "string"); }
  function validNode(node) {
    return node && nodeStringKeys.every(key => typeof node[key] === "string") && typeof node.protected === "boolean" &&
      nodeKinds.has(node.kind) && availabilityTypes.has(node.availability) && node.online_label === "未检测" &&
      (node.kind === "hub" ? node.id === "hub" && node.availability === "hub" : node.id.startsWith(`${node.kind}:`) && node.availability !== "hub");
  }
  function sameNode(first, second) {
    return validNode(first) && second && [...nodeStringKeys, "protected"].every(key => first[key] === second[key]);
  }
  function validDirection(direction) {
    return direction && permissionTypes.has(direction.status) && typeof direction.label === "string" &&
      typeof direction.summary === "string" && stringList(direction.scopes) && stringList(direction.warnings);
  }
  function validSnapshot(value) {
    if (!value || !Array.isArray(value.nodes) || !value.nodes.every(validNode) ||
      value.nodes.filter(node => node.kind === "hub").length !== 1 || typeof value.selected_id !== "string" ||
      !Array.isArray(value.relations) || !stringList(value.warnings) || typeof value.note !== "string" ||
      typeof value.observed_at !== "string" || !value.summary ||
      !["nodes", "awg", "vless", "enabled", "disabled", "pending"].every(key => Number.isInteger(value.summary[key]) && value.summary[key] >= 0)) return false;
    const nodes = new Map(value.nodes.map(node => [node.id, node]));
    if (nodes.size !== value.nodes.length || !sameNode(value.selected, nodes.get(value.selected_id)) ||
      value.selected.id !== value.selected_id || value.relations.length !== nodes.size - 1) return false;
    const related = new Set();
    for (const relation of value.relations) {
      if (!relation || !validNode(relation.node) || relation.node.id === value.selected_id || related.has(relation.node.id) ||
        !sameNode(relation.node, nodes.get(relation.node.id)) || !relationTypes.has(relation.relation) || typeof relation.label !== "string" ||
        !validDirection(relation.forward) || !validDirection(relation.reverse)) return false;
      related.add(relation.node.id);
    }
    return true;
  }
  try {
    snapshot = JSON.parse(initial.textContent);
    if (!validSnapshot(snapshot)) return;
  } catch (_) { return; }

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function svgElement(tag, attributes) {
    const node = document.createElementNS(svgNS, tag);
    Object.entries(attributes).forEach(([name, value]) => node.setAttribute(name, String(value)));
    return node;
  }
  function relationType(relation) { return relation && relationTypes.has(relation.relation) ? relation.relation : "unknown"; }
  function compactGraph() { return graph.clientWidth < 640 || window.matchMedia("(max-width: 600px)").matches; }
  function pageSize() { return compactGraph() ? 5 : 7; }
  function filteredNodes() {
    const query = search.value.trim().toLocaleLowerCase();
    return snapshot.nodes.filter(node => node.kind !== "hub" && (!query || [node.name, node.address, node.kind_label, node.kind].join(" ").toLocaleLowerCase().includes(query)));
  }
  function fitPageToSelected() {
    const index = filteredNodes().findIndex(node => node.id === snapshot.selected_id);
    if (index >= 0) page = Math.floor(index / pageSize());
  }
  function setStatus(message, state) {
    status.textContent = message;
    status.dataset.state = state || "ready";
  }
  function timestamp(value) {
    if (!value) return "未提供";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString("zh-CN", {hour12: false});
  }
  function renderObservedAt() {
    const observed = root.querySelector("[data-topology-observed-at]");
    observed.textContent = timestamp(snapshot.observed_at);
    if (snapshot.observed_at) observed.setAttribute("datetime", snapshot.observed_at);
  }
  function renderSelect() {
    const options = document.createDocumentFragment();
    snapshot.nodes.forEach(node => {
      const option = element("option", "", `${node.name} · ${node.kind_label}`);
      option.value = node.id;
      option.selected = node.id === snapshot.selected_id;
      options.append(option);
    });
    select.replaceChildren(options);
  }
  function directionList(direction) {
    const list = element("ul", "topology-relations");
    list.setAttribute(direction === "forward" ? "data-topology-outbound" : "data-topology-inbound", "");
    if (!snapshot.relations.length) {
      list.append(element("li", "topology-relations-empty", "尚无其他节点。添加节点后将在此显示访问关系。"));
      return list;
    }
    snapshot.relations.forEach(relation => {
      const permission = relation[direction];
      const state = permissionTypes.has(permission.status) ? permission.status : "unknown";
      const row = element("li", "topology-relation");
      row.dataset.relationStatus = state;
      const heading = element("div", "topology-relation-heading");
      heading.append(element("strong", "", relation.node.name), element("span", `topology-permission permission-${state}`, permission.label || "未知"));
      const from = direction === "forward" ? snapshot.selected : relation.node;
      const to = direction === "forward" ? relation.node : snapshot.selected;
      const path = [from.name];
      if (from.kind !== "hub" && to.kind !== "hub") path.push("VPS");
      path.push(to.name);
      row.append(heading, element("p", "topology-path", path.join(" → ")), element("p", "topology-relation-summary", permission.summary || "当前配置无法确定此方向的授权。"));
      if (Array.isArray(permission.scopes) && permission.scopes.length) {
        const scopes = element("ul", "topology-scopes");
        scopes.setAttribute("aria-label", "配置范围");
        permission.scopes.forEach(scope => scopes.append(element("li", "", scope)));
        row.append(scopes);
      }
      if (Array.isArray(permission.warnings)) permission.warnings.forEach(warning => row.append(element("p", "topology-relation-warning", warning)));
      list.append(row);
    });
    return list;
  }
  function renderDetails() {
    const selected = snapshot.selected;
    const summary = element("div", "topology-selected");
    const identity = element("div");
    const title = element("h2", "", selected.name);
    title.id = "topology-selected-heading";
    identity.append(element("p", "eyebrow", "当前观察节点"), title, element("p", "", [selected.kind_label, selected.address].filter(Boolean).join(" · ")));
    const facts = element("dl");
    const entries = [["配置状态", selected.state || "未知"], ["在线状态", selected.online_label || "未检测"]];
    if (selected.protected) entries.push(["节点角色", "管理入口"]);
    entries.forEach(([label, value]) => {
      const fact = element("div");
      fact.append(element("dt", "", label), element("dd", "", value));
      facts.append(fact);
    });
    summary.append(identity, facts);
    const directions = element("div", "topology-direction-grid");
    [["forward", "outbound", "我可访问", "从当前节点发起连接", "↗"], ["reverse", "inbound", "可访问我", "从其他节点发起连接", "↙"]].forEach(([key, name, label, subtitle, arrow]) => {
      const section = element("section", "topology-direction");
      section.setAttribute("aria-labelledby", `topology-${name}-heading`);
      const heading = element("div", "topology-direction-heading");
      const icon = element("span", "", arrow);
      icon.setAttribute("aria-hidden", "true");
      const headingText = element("div");
      const title = element("h3", "", label);
      title.id = `topology-${name}-heading`;
      headingText.append(title, element("p", "", subtitle));
      heading.append(icon, headingText);
      section.append(heading, directionList(key));
      directions.append(section);
    });
    details.replaceChildren(summary, element("p", "topology-detail-note", "以下为配置允许的方向，允许部分端口不等于完全互通。目标的防火墙、服务与实际在线情况仍可能影响连接。"), directions);
    root.querySelectorAll("[data-topology-count]").forEach(counter => { counter.textContent = snapshot.summary?.[counter.dataset.topologyCount] ?? "—"; });
    const warnings = root.querySelector("[data-topology-warnings]");
    const notes = Array.isArray(snapshot.warnings) ? snapshot.warnings : [];
    warnings.replaceChildren(...notes.map(warning => element("p", "alert neutral", warning)));
    warnings.hidden = !notes.length;
    if (snapshot.note) root.querySelector("[data-topology-note]").textContent = snapshot.note;
    renderObservedAt();
  }
  function nodeButton(node, relation, x, y, width) {
    const chosen = node.id === snapshot.selected_id;
    const button = element("button", `topology-node relation-${relationType(relation)} availability-${node.availability}${node.kind === "hub" ? " is-hub" : ""}`);
    button.type = "button";
    button.dataset.topologyNode = node.id;
    button.setAttribute("aria-pressed", chosen ? "true" : "false");
    const label = chosen ? "当前观察节点" : relation?.label || (node.kind === "hub" ? "中心网关" : "授权未知");
    button.setAttribute("aria-label", `${node.name}，${node.kind_label}，${node.state || "配置状态未知"}，在线${node.online_label || "未检测"}，${label}`);
    button.title = `${node.name} · ${node.address || node.kind_label} · ${label}`;
    button.style.left = `${x}px`;
    button.style.top = `${y}px`;
    if (width) button.style.width = `${width}px`;
    const kicker = element("span", "topology-node-kicker");
    kicker.append(element("span", "", node.kind === "hub" ? "中心网关" : node.kind.toUpperCase()));
    if (node.kind !== "hub") kicker.append(element("span", "", node.state || "状态未知"));
    button.append(kicker, element("strong", "", node.name), element("span", "topology-node-relation", label));
    button.addEventListener("click", () => load(node.id));
    return button;
  }
  function rayEndpoint(x, y, dx, dy, halfWidth, halfHeight) {
    const fraction = Math.min(Math.abs(halfWidth / (dx || 0.0001)), Math.abs(halfHeight / (dy || 0.0001)));
    return {x: x + dx * fraction, y: y + dy * fraction};
  }
  function renderGraph() {
    const active = document.activeElement;
    const focusedId = graph.contains(active) ? active.dataset.topologyNode : null;
    const width = graph.clientWidth;
    if (!width) return;
    const narrow = compactGraph();
    graph.dataset.compact = narrow ? "true" : "false";
    const height = graph.clientHeight;
    const all = filteredNodes();
    const size = pageSize();
    const pages = Math.max(1, Math.ceil(all.length / size));
    page = Math.max(0, Math.min(page, pages - 1));
    const visible = all.slice(page * size, (page + 1) * size);
    const cx = width / 2;
    const cy = height / 2;
    const nodeWidth = narrow ? Math.min(112, (width - 18) / 2) : Math.min(156, width / 3.6);
    const hubWidth = narrow ? 116 : 152;
    const rx = Math.max(20, (width - nodeWidth) / 2 - (narrow ? 5 : 15));
    const ry = narrow ? 210 : 162;
    const diagram = svgElement("svg", {viewBox: `0 0 ${width} ${height}`, "aria-hidden": "true", focusable: "false"});
    const defs = svgElement("defs", {});
    const marker = svgElement("marker", {id: "topology-arrow", viewBox: "0 0 10 10", refX: 8, refY: 5, markerWidth: 5, markerHeight: 5, orient: "auto-start-reverse"});
    marker.append(svgElement("path", {d: "M 1 1 L 9 5 L 1 9", fill: "none", stroke: "context-stroke", "stroke-width": 1.6, "stroke-linecap": "round", "stroke-linejoin": "round"}));
    defs.append(marker);
    diagram.append(defs, svgElement("ellipse", {cx, cy, rx, ry, class: "topology-orbit"}));
    const relationMap = new Map(snapshot.relations.map(relation => [relation.node.id, relation]));
    const fragment = document.createDocumentFragment();
    fragment.append(diagram);
    const mobileAngles = {1: [-90], 2: [-90, 90], 3: [-90, 30, 150], 4: [-30, 30, 150, 210], 5: [-90, -30, 30, 150, 210]};
    visible.forEach((node, index) => {
      const degrees = narrow ? mobileAngles[visible.length][index] : -90 + index * 360 / visible.length;
      const angle = degrees * Math.PI / 180;
      const x = cx + Math.cos(angle) * rx;
      // Lift the side nodes clear of the hub so both arrowheads remain visible
      // on narrow screens. The top/bottom positions retain extra label space.
      const y = cy + (narrow && Math.abs(Math.cos(angle)) > 0.1 ? Math.sign(Math.sin(angle)) * 122 : Math.sin(angle) * ry);
      const relation = relationMap.get(node.id);
      const start = rayEndpoint(x, y, cx - x, cy - y, nodeWidth / 2 + 5, (narrow ? 72 : 82) / 2 + 5);
      const end = rayEndpoint(cx, cy, x - cx, y - cy, hubWidth / 2 + 7, (narrow ? 84 : 106) / 2 + 7);
      const line = svgElement("line", {x1: start.x, y1: start.y, x2: end.x, y2: end.y, "data-topology-edge": "", "data-source": node.id, "data-target": "hub", class: `topology-edge relation-${relationType(relation)}${node.id === snapshot.selected_id ? " is-selected" : ""}`, "marker-end": "url(#topology-arrow)"});
      if (node.kind === "awg") line.setAttribute("marker-start", "url(#topology-arrow)");
      diagram.append(line);
      fragment.append(nodeButton(node, relation, x, y, nodeWidth));
    });
    const hub = snapshot.nodes.find(node => node.id === "hub");
    fragment.append(nodeButton(hub, relationMap.get("hub"), cx, cy));
    if (!visible.length) fragment.append(element("p", "topology-graph-empty", search.value.trim() ? "没有匹配的节点；可清空搜索或用上方选择框查看。" : "尚无设备节点，可在节点管理中添加。"));
    graph.replaceChildren(fragment);
    if (focusedId) {
      const target = [...graph.querySelectorAll("[data-topology-node]")].find(button => button.dataset.topologyNode === focusedId);
      if (target) target.focus({preventScroll: true});
    }
    const total = snapshot.nodes.filter(node => node.kind !== "hub").length;
    const range = all.length ? `${page * size + 1}–${Math.min((page + 1) * size, all.length)}` : "0";
    const filtering = search.value.trim() ? `匹配 ${all.length} / 共 ${total} 个设备` : `共 ${total} 个设备`;
    root.querySelector("[data-topology-page]").textContent = `${filtering} · 当前 ${range} · 第 ${page + 1} / ${pages} 页`;
    prev.disabled = page === 0;
    next.disabled = page >= pages - 1;
  }
  function scheduleGraph() {
    if (layoutFrame !== null) cancelAnimationFrame(layoutFrame);
    layoutFrame = requestAnimationFrame(() => { layoutFrame = null; renderGraph(); });
  }
  async function load(id, isRefresh = false) {
    if (id === snapshot.selected_id && !isRefresh) {
      if (controller && requestedId !== id) { controller.abort(); generation += 1; controller = null; requestedId = null; refresh.disabled = false; root.removeAttribute("aria-busy"); }
      select.value = snapshot.selected_id;
      setStatus(`当前观察：${snapshot.selected.name}。在线状态未检测。`);
      return;
    }
    if (controller) controller.abort();
    const thisGeneration = ++generation;
    controller = new AbortController();
    const activeController = controller;
    const signal = controller.signal;
    let timedOut = false;
    const timeout = window.setTimeout(() => {
      if (thisGeneration !== generation) return;
      timedOut = true;
      activeController.abort();
    }, 15000);
    requestedId = id;
    refresh.disabled = true;
    root.setAttribute("aria-busy", "true");
    setStatus(isRefresh ? "正在重新读取配置…" : "正在读取所选节点的访问关系…", "loading");
    try {
      const url = new URL(form.action, window.location.href);
      url.searchParams.set("node", id);
      url.searchParams.set("format", "json");
      const response = await fetch(url.href, {method: "GET", credentials: "same-origin", cache: "no-store", headers: {Accept: "application/json"}, signal});
      if (!response.ok || !response.headers.get("content-type")?.includes("application/json")) throw new Error("unavailable");
      const nextSnapshot = await response.json();
      if (!validSnapshot(nextSnapshot)) throw new Error("invalid-snapshot");
      if (thisGeneration !== generation || signal.aborted) return;
      snapshot = nextSnapshot;
      renderSelect();
      renderDetails();
      fitPageToSelected();
      renderGraph();
      const location = new URL(window.location.href);
      location.searchParams.set("node", snapshot.selected_id);
      location.searchParams.delete("format");
      window.history.replaceState(null, "", location.href);
      setStatus(`已读取 ${snapshot.selected.name} 的配置关系。在线状态未检测。`);
    } catch (error) {
      if (thisGeneration !== generation || (signal.aborted && !timedOut)) return;
      select.value = snapshot.selected_id;
      setStatus(timedOut ? "读取超时，已保留上次显示的配置。请稍后刷新。" : "读取失败，已保留上次显示的配置。请稍后刷新；若登录已过期，请重新登录。", "error");
    } finally {
      window.clearTimeout(timeout);
      if (thisGeneration === generation) {
        controller = null;
        requestedId = null;
        refresh.disabled = false;
        root.removeAttribute("aria-busy");
      }
    }
  }

  root.querySelector("[data-topology-enhancement]").hidden = false;
  root.querySelector("[data-topology-submit]").hidden = true;
  refresh.hidden = false;
  form.addEventListener("submit", event => { event.preventDefault(); load(select.value); });
  select.addEventListener("change", () => load(select.value));
  refresh.addEventListener("click", () => load(snapshot.selected_id, true));
  search.addEventListener("input", () => { page = 0; renderGraph(); });
  prev.addEventListener("click", () => { page -= 1; renderGraph(); });
  next.addEventListener("click", () => { page += 1; renderGraph(); });
  if ("ResizeObserver" in window) new ResizeObserver(scheduleGraph).observe(graph);
  else window.addEventListener("resize", scheduleGraph);
  window.addEventListener("pagehide", () => {
    generation += 1;
    if (controller) controller.abort();
    controller = null;
    requestedId = null;
    if (layoutFrame !== null) cancelAnimationFrame(layoutFrame);
    layoutFrame = null;
    refresh.disabled = false;
    root.removeAttribute("aria-busy");
    select.value = snapshot.selected_id;
    setStatus(`当前观察：${snapshot.selected.name}。在线状态未检测。`);
  });
  window.addEventListener("pageshow", scheduleGraph);
  fitPageToSelected();
  renderObservedAt();
  renderGraph();
})();
