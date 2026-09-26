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
  const inspector = root.querySelector("[data-topology-inspector]");
  const findNext = root.querySelector("[data-topology-find-next]");
  const status = root.querySelector("[data-topology-status]");
  const details = root.querySelector("[data-topology-details]");
  const svgNS = "http://www.w3.org/2000/svg";
  const relationTypes = new Set(["mutual", "outbound", "inbound", "denied", "unknown", "not_applicable"]);
  const permissionTypes = new Set(["allowed", "partial", "denied", "inactive", "unknown", "not_applicable"]);
  const nodeKinds = new Set(["hub", "awg", "vless"]);
  const availabilityTypes = new Set(["hub", "enabled", "disabled", "pending", "unknown"]);
  const nodeStringKeys = ["id", "name", "kind", "kind_label", "address", "state", "availability", "online_label"];
  let snapshot;
  let controller = null;
  let generation = 0;
  let layoutFrame = null;
  let requestedId = null;
  const positions = new Map();
  const pointers = new Map();
  const view = {x: 0, y: 0, scale: 1, width: 0, height: 0, fitted: true};
  let scene = null;
  let drawingKey = "";
  let gesture = null;
  let suppressClickUntil = 0;
  let searchIndex = 0;
  let pointerFrame = null;
  let restoringFocus = false;
  let userAdjustedView = false;
  let layoutAspect = null;
  let displayMode = "overview";
  let direction = "forward";
  const dirtyNodes = new Set();

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
      !Array.isArray(value.relations) || !Array.isArray(value.links) || !stringList(value.warnings) || typeof value.note !== "string" ||
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
    const links = new Set();
    for (const link of value.links) {
      if (!link || typeof link.source !== "string" || typeof link.target !== "string" || link.source === link.target ||
        !nodes.has(link.source) || !nodes.has(link.target) || !["allowed", "partial"].includes(link.status) ||
        typeof link.label !== "string" || !stringList(link.scopes) || !link.scopes.length) return false;
      const source = nodes.get(link.source), target = nodes.get(link.target);
      if (source.kind === "hub" || target.kind === "vless" || source.availability !== "enabled" ||
        !["enabled", "hub"].includes(target.availability)) return false;
      const key = JSON.stringify([link.source, link.target]);
      if (links.has(key)) return false;
      links.add(key);
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
  function matchingNodes() {
    const query = search.value.trim().toLocaleLowerCase();
    return query ? snapshot.nodes.filter(node => [node.name, node.address, node.kind_label, node.kind].join(" ").toLocaleLowerCase().includes(query)) : [];
  }
  function visibleLinks() {
    if (displayMode === "overview") return [];
    return snapshot.links.filter(link => (direction === "forward" ? link.source : link.target) === snapshot.selected_id);
  }
  function directionHint() {
    return direction === "forward" ? "端口写在目标节点内，完整范围见详情。"
      : "卡片端口表示该节点可访问当前节点的范围。";
  }
  function compactScope(scope) {
    if (scope === "全部协议 · 全部端口") return "全协议 · 全端口";
    return scope.replaceAll(" · ", " ").replaceAll(", ", ",");
  }
  function renderInspector() {
    if (!inspector) return;
    const selected = snapshot.selected;
    if (displayMode === "overview") {
      const icon = element("span", "topology-inspector-icon", "◎");
      icon.setAttribute("aria-hidden", "true");
      inspector.replaceChildren(icon, element("h3", "", "先看结构，再看权限"),
        element("p", "", "所有节点经 VPS 中转。点一个节点，查看它能访问谁、开放哪些端口。"),
        element("p", "topology-inspector-hint", "虚线仅表示接入配置，在线状态未检测。"));
      return;
    }
    const allowed = snapshot.relations.filter(relation => ["allowed", "partial"].includes(relation[direction].status));
    const heading = element("div", "topology-inspector-heading");
    heading.append(element("p", "eyebrow", "当前节点"), element("h3", "", selected.name),
      element("p", "", [selected.kind_label, selected.address].filter(Boolean).join(" · ")));
    const title = element("h4", "", `${direction === "forward" ? "我可访问" : "可访问我"} · ${allowed.length}`);
    const list = element("ul", "topology-access-list");
    allowed.forEach(relation => {
      const row = element("li", "topology-access-item");
      row.dataset.topologyAccessTarget = relation.node.id;
      const target = element("button", "topology-access-target", relation.node.name);
      target.type = "button";
      target.title = "在图中定位此节点";
      target.addEventListener("click", () => centerNode(relation.node.id, true));
      const scopes = element("ul", "topology-access-scopes");
      relation[direction].scopes.forEach(scope => scopes.append(element("li", "", scope)));
      row.append(target, scopes);
      list.append(row);
    });
    if (!allowed.length) list.append(element("li", "topology-inspector-hint", "此方向没有已确认的授权。未知、禁用及未授权情况请查看完整权限。"));
    const full = element("button", "secondary-button topology-open-details", `完整权限 · ${snapshot.relations.length} 个目标`);
    full.type = "button";
    full.addEventListener("click", () => {
      const section = root.querySelector("[data-topology-full-details]");
      if (section) { section.open = true; section.scrollIntoView({block: "start", behavior: "smooth"}); }
    });
    inspector.replaceChildren(heading, title, list, full,
      element("p", "topology-inspector-hint", "这里只列配置允许的范围，不代表实时连通。"));
  }
  function syncModeControls() {
    root.dataset.topologyMode = displayMode;
    graph.dataset.mode = displayMode;
    graph.dataset.direction = direction;
    root.querySelectorAll("[data-topology-mode]").forEach(button => button.setAttribute("aria-pressed", String(button.dataset.topologyMode === displayMode)));
    root.querySelectorAll("[data-topology-direction]").forEach(button => button.setAttribute("aria-pressed", String(button.dataset.topologyDirection === direction)));
    const controls = root.querySelector("[data-topology-direction-controls]");
    if (controls) controls.hidden = displayMode !== "relations";
    renderInspector();
  }
  function setMode(mode) {
    if (mode === "overview" && controller) {
      controller.abort(); generation += 1; controller = null; requestedId = null;
      refresh.disabled = false; root.removeAttribute("aria-busy"); select.value = snapshot.selected_id;
    }
    displayMode = mode;
    syncModeControls(); renderGraph();
    setStatus(mode === "overview" ? "全部节点都在图中。点击节点查看端口。" : directionHint());
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
  function measuredAspect() {
    return graph.clientWidth;
  }
  function nodeSize() {
    const style = getComputedStyle(graph);
    return {width: parseFloat(style.getPropertyValue("--topology-node-width")) || 148,
      height: parseFloat(style.getPropertyValue("--topology-node-height")) || 104};
  }
  function sizeCanvas() {
    const rows = Math.ceil((snapshot.nodes.length - 1) / 2);
    const height = Math.max(480, Math.min(1120, rows * (nodeSize().height + 32) + (graph.clientWidth < 520 ? 200 : 100)));
    graph.style.height = `${height}px`;
  }
  function syncPositions(rearrange = false) {
    const ids = new Set(snapshot.nodes.map(node => node.id));
    for (const id of positions.keys()) if (!ids.has(id)) positions.delete(id);
    if (rearrange) positions.clear();
    if (!positions.size) {
      positions.set("hub", {x: 0, y: 0});
      const clients = snapshot.nodes.filter(node => node.id !== "hub");
      layoutAspect = measuredAspect();
      const rows = Math.ceil(clients.length / 2), compact = graph.clientWidth < 520;
      const spacing = Math.max(76, (graph.clientWidth - nodeSize().width - 32) / 2);
      clients.forEach((node, index) => {
        const column = index % 2, row = Math.floor(index / 2);
        let y = (row - (rows - 1) / 2) * (nodeSize().height + 32);
        const hubGap = nodeSize().height + 16;
        if (compact) y += y < 0 ? -hubGap : y > 0 ? hubGap : column ? hubGap : -hubGap;
        positions.set(node.id, {x: column ? spacing : -spacing, y});
      });
    }
    for (const node of snapshot.nodes) if (!positions.has(node.id)) {
      let candidate, index = positions.size;
      do {
        const angle = index * 2.3999632297;
        const radius = 110 * Math.sqrt(index + 1);
        candidate = {x: Math.cos(angle) * radius, y: Math.sin(angle) * radius};
        index += 1;
      } while ([...positions.values()].some(position => Math.hypot(position.x - candidate.x, position.y - candidate.y) < 105));
      positions.set(node.id, candidate);
    }
  }
  function applyView(redrawEdges = false) {
    if (!scene) return;
    scene.world.style.transform = `translate(${view.x}px, ${view.y}px) scale(${view.scale})`;
    scene.world.style.setProperty("--topology-inverse-scale", String(1 / view.scale));
    scene.marker.setAttribute("markerWidth", String(10 / view.scale));
    scene.marker.setAttribute("markerHeight", String(10 / view.scale));
    graph.dataset.viewportX = String(view.x);
    graph.dataset.viewportY = String(view.y);
    graph.dataset.viewportScale = String(view.scale);
    root.querySelector("[data-topology-zoom]").textContent = `${Math.round(view.scale * 100)}%`;
    if (redrawEdges || scene.geometryScale !== view.scale) {
      scene.spokes.forEach(drawSpoke); scene.edges.forEach(drawLink);
      scene.geometryScale = view.scale;
    }
  }
  function fitAll() {
    if (!positions.size) return;
    const points = [...positions.values()];
    const xs = points.map(point => point.x), ys = points.map(point => point.y);
    const minX = Math.min(...xs), maxX = Math.max(...xs), minY = Math.min(...ys), maxY = Math.max(...ys);
    view.width = graph.clientWidth; view.height = graph.clientHeight;
    const size = nodeSize();
    view.scale = Math.max(.03, Math.min(1, (view.width - size.width - 32) / Math.max(1, maxX - minX), (view.height - size.height - 64) / Math.max(1, maxY - minY)));
    view.x = view.width / 2 - (minX + maxX) / 2 * view.scale;
    view.y = view.height / 2 - (minY + maxY) / 2 * view.scale;
    view.fitted = true;
    applyView(true);
  }
  function zoomAt(factor, x = graph.clientWidth / 2, y = graph.clientHeight / 2) {
    userAdjustedView = true;
    const scale = Math.max(.03, Math.min(3.5, view.scale * factor));
    const ratio = scale / view.scale;
    view.x = x - (x - view.x) * ratio; view.y = y - (y - view.y) * ratio;
    view.scale = scale; view.fitted = false;
    applyView();
  }
  function centerNode(id, enlarge = false) {
    const position = positions.get(id);
    if (!position) return;
    userAdjustedView = true;
    if (enlarge) view.scale = Math.max(.9, view.scale);
    view.x = graph.clientWidth / 2 - position.x * view.scale;
    view.y = graph.clientHeight / 2 - position.y * view.scale;
    view.fitted = false;
    applyView();
  }
  function updateGeometry(id) {
    const position = positions.get(id), button = scene.nodes.get(id);
    if (!position || !button) return;
    button.style.left = `${position.x}px`; button.style.top = `${position.y}px`;
    button.dataset.worldX = String(position.x); button.dataset.worldY = String(position.y);
  }
  function drawSpoke(spoke) {
    const origin = positions.get(spoke.source), center = positions.get("hub");
    const from = cardEdge(origin, center), to = cardEdge(center, origin);
    spoke.line.setAttribute("x1", from.x); spoke.line.setAttribute("y1", from.y);
    spoke.line.setAttribute("x2", to.x); spoke.line.setAttribute("y2", to.y);
  }
  function cardEdge(from, toward) {
    const size = nodeSize(), dx = toward.x - from.x, dy = toward.y - from.y;
    const fraction = Math.min(.48, (size.width / 2 + 7) / view.scale / Math.max(.01, Math.abs(dx)),
      (size.height / 2 + 7) / view.scale / Math.max(.01, Math.abs(dy)));
    return {x: from.x + dx * fraction, y: from.y + dy * fraction};
  }
  function drawLink(edge) {
    const start = positions.get(edge.source), end = positions.get(edge.target);
    const dx = end.x - start.x, dy = end.y - start.y, length = Math.max(1, Math.hypot(dx, dy));
    const bend = Math.min(36, length * .05);
    let cx = (start.x + end.x) / 2 - dy / length * bend;
    const cy = (start.y + end.y) / 2 + dx / length * bend;
    // Route same-column permissions through the empty centre lane, not through
    // intermediate device cards. Moving a card still gives it a free curve.
    if (Math.abs(dx) < 1 && start.x !== 0) cx = graph.clientWidth < 520 ? -start.x : 0;
    const from = cardEdge(start, {x: cx, y: cy}), to = cardEdge(end, {x: cx, y: cy});
    edge.path.setAttribute("d", `M ${from.x} ${from.y} Q ${cx} ${cy} ${to.x} ${to.y}`);
  }
  function updateGraphFacts() {
    const matched = new Set(matchingNodes().map(node => node.id));
    const relations = new Map(snapshot.relations.map(relation => [relation.node.id, relation]));
    // Highlight only the opposite endpoint of the permissions actually drawn
    // for this direction. Never turn a spoke or an unknown relation into access.
    const peers = new Map(displayMode === "relations"
      ? scene.edges.map(edge => [direction === "forward" ? edge.target : edge.source, edge]) : []);
    for (const node of snapshot.nodes) {
      const button = scene.nodes.get(node.id), chosen = node.id === snapshot.selected_id;
      const relation = relations.get(node.id);
      const peer = !chosen && peers.has(node.id);
      const scopes = peer ? peers.get(node.id).scopes : [];
      const scopeRole = direction === "forward" ? "当前节点可访问此节点" : "此节点可访问当前节点";
      const role = chosen ? "当前观察节点" : peer
        ? `${direction === "forward" ? "已授权目标" : "已授权来源"}，${relation?.[direction].label || "已授权"}`
        : relation?.label || "中心网关";
      button.className = `topology-node kind-${node.kind} availability-${node.availability}${node.kind === "hub" ? " is-hub" : ""}${matched.has(node.id) ? " is-match" : ""}${peer ? " is-peer" : ""}`;
      if (peer) button.dataset.topologyPeer = direction === "forward" ? "outbound" : "inbound";
      else delete button.dataset.topologyPeer;
      button.setAttribute("aria-pressed", String(chosen));
      const scopeText = scopes.length ? `。${scopeRole}：${scopes.join("；")}` : "";
      button.setAttribute("aria-label", `${node.name}，${node.kind_label}，${node.state}，在线未检测，${role}${scopeText}。可拖动调整布局。`);
      button.title = `${node.name} · ${node.kind_label}${node.address ? ` · ${node.address}` : ""} · ${node.state} · ${role}${scopeText} · 在线未检测`;
      button.querySelector("strong").textContent = node.name;
      button.querySelector(".topology-node-state").textContent = node.kind === "hub" ? "中心网关" : [node.kind.toUpperCase(), node.availability !== "enabled" ? node.state : ""].filter(Boolean).join(" · ");
      button.querySelector(".topology-node-selected").hidden = !chosen || displayMode !== "relations";
      const ports = button.querySelector("[data-topology-node-ports]");
      ports.replaceChildren();
      ports.hidden = !scopes.length;
      ports.removeAttribute("title");
      ports.removeAttribute("aria-label");
      if (scopes.length) {
        ports.title = `${scopeRole}：${scopes.join("；")}`;
        ports.setAttribute("aria-label", ports.title);
        scopes.slice(0, 2).forEach(scope => {
          const line = element("span", "topology-node-port", compactScope(scope));
          line.dataset.topologyScope = scope;
          line.title = scope;
          ports.append(line);
        });
        if (scopes.length > 2) ports.append(element("span", "topology-node-ports-more", `另 ${scopes.length - 2} 项·见详情`));
      }
    }
    const related = new Set(scene.edges.flatMap(edge => [edge.source, edge.target]));
    for (const [id, button] of scene.nodes) button.classList.toggle("is-related", related.has(id));
    scene.world.dataset.mode = displayMode;
    const matchLabel = search.value.trim() ? ` · 搜索匹配 ${matched.size} 个` : "";
    root.querySelector("[data-topology-canvas-summary]").textContent = `全部 ${snapshot.nodes.length} 个节点（含 VPS）${displayMode === "relations" ? ` · 当前方向 ${scene.edges.length} 条授权` : " · 经 VPS 中转"}${matchLabel}`;
    findNext.disabled = !matched.size;
  }
  function renderGraph() {
    sizeCanvas();
    if (!graph.clientWidth || !graph.clientHeight) {
      if (layoutFrame !== null) cancelAnimationFrame(layoutFrame);
      layoutFrame = requestAnimationFrame(() => { layoutFrame = null; renderGraph(); });
      return;
    }
    if (gesture?.id && !snapshot.nodes.some(node => node.id === gesture.id)) cancelGesture();
    syncPositions();
    const links = visibleLinks();
    const key = JSON.stringify([snapshot.nodes.map(node => node.id), links, displayMode, direction]);
    if (scene && drawingKey === key) { updateGraphFacts(); return; }
    const focusedId = graph.contains(document.activeElement) ? document.activeElement.dataset.topologyNode : null;
    const world = element("div", "topology-world");
    world.setAttribute("data-topology-world", "");
    const diagram = svgElement("svg", {"aria-hidden": "true", focusable: "false"});
    const marker = svgElement("marker", {id: "topology-arrow", viewBox: "0 0 10 10", refX: 8, refY: 5, markerWidth: 10, markerHeight: 10, markerUnits: "userSpaceOnUse", orient: "auto"});
    marker.append(svgElement("path", {d: "M 1 1 L 8 5 L 1 9", fill: "none", class: "topology-arrow", "stroke-width": 1.5, "stroke-linecap": "round", "stroke-linejoin": "round"}));
    const definitions = svgElement("defs", {}); definitions.append(marker); diagram.append(definitions);
    scene = {world, marker, nodes: new Map(), edges: [], spokes: [], incidents: new Map(snapshot.nodes.map(node => [node.id, new Set()]))};
    for (const node of snapshot.nodes) if (node.id !== "hub") {
      const line = svgElement("line", {class: "topology-spoke", "data-topology-spoke": "", "data-source": node.id, "data-target": "hub"});
      const spoke = {source: node.id, line}; scene.spokes.push(spoke); diagram.append(line); drawSpoke(spoke);
    }
    const pathsLayer = svgElement("g", {});
    diagram.append(pathsLayer);
    const nodeNames = new Map(snapshot.nodes.map(node => [node.id, node.name]));
    for (const link of links) {
      const linkKey = `${link.source}→${link.target}`;
      const group = svgElement("g", {class: "topology-link is-connected", "data-topology-link": "", "data-link-key": linkKey});
      const path = svgElement("path", {class: "topology-edge", "data-topology-edge": "", "data-source": link.source, "data-target": link.target, "data-link-key": linkKey, "data-bidirectional": "false", "marker-end": "url(#topology-arrow)"});
      const full = `${nodeNames.get(link.source)} → ${nodeNames.get(link.target)}：${link.label}`;
      const title = svgElement("title", {}); title.textContent = full;
      group.append(title, path); pathsLayer.append(group);
      const edge = {...link, group, path};
      scene.edges.push(edge); scene.incidents.get(link.source).add(edge); scene.incidents.get(link.target).add(edge); drawLink(edge);
    }
    world.append(diagram);
    for (const node of snapshot.nodes) {
      const button = element("button", "topology-node"); button.type = "button"; button.dataset.topologyNode = node.id;
      const dot = element("span", "topology-node-dot"); dot.setAttribute("aria-hidden", "true");
      const ports = element("span", "topology-node-ports"); ports.dataset.topologyNodePorts = "";
      const selected = element("span", "topology-node-selected", "当前"); selected.setAttribute("aria-hidden", "true");
      button.append(dot, element("strong", "", node.name), element("span", "topology-node-state"), selected, ports);
      scene.nodes.set(node.id, button); world.append(button); updateGeometry(node.id);
    }
    graph.replaceChildren(world);
    if (snapshot.nodes.length === 1) graph.append(element("p", "topology-graph-empty", "尚无设备节点，可在节点列表中添加。"));
    drawingKey = key;
    updateGraphFacts();
    if (!view.width) fitAll(); else applyView(true);
    if (focusedId && scene.nodes.has(focusedId)) { restoringFocus = true; scene.nodes.get(focusedId).focus({preventScroll: true}); restoringFocus = false; }
  }
  function flushPointers() {
    pointerFrame = null;
    if (!scene) return;
    const changedEdges = new Set();
    for (const id of dirtyNodes) {
      updateGeometry(id);
      for (const edge of scene.incidents.get(id) || []) changedEdges.add(edge);
    }
    for (const edge of changedEdges) drawLink(edge);
    for (const spoke of scene.spokes) if (dirtyNodes.has(spoke.source) || dirtyNodes.has("hub")) drawSpoke(spoke);
    const redrawEdges = dirtyNodes.size > 0;
    dirtyNodes.clear(); applyView(redrawEdges);
  }
  function schedulePointers() { if (pointerFrame === null) pointerFrame = requestAnimationFrame(flushPointers); }
  function scheduleGraph() {
    if (layoutFrame !== null) cancelAnimationFrame(layoutFrame);
    layoutFrame = requestAnimationFrame(() => {
      layoutFrame = null;
      if (!scene) { renderGraph(); return; }
      const width = graph.clientWidth, height = graph.clientHeight;
      if (width === view.width && height === view.height && (userAdjustedView || Math.abs(layoutAspect - measuredAspect()) < .01)) return;
      if (!userAdjustedView) {
        // The first ResizeObserver notification can arrive after CSS settles
        // or an initial mobile viewport is applied. Only the untouched default
        // layout may adapt its aspect ratio; never replace a user's layout.
        syncPositions(true);
        for (const id of positions.keys()) dirtyNodes.add(id);
        flushPointers(); fitAll();
      } else if (view.fitted) fitAll();
      else { view.x += (width - view.width) / 2; view.y += (height - view.height) / 2; view.width = width; view.height = height; applyView(true); }
    });
  }
  function localPoint(event) {
    const bounds = graph.getBoundingClientRect();
    return {x: event.clientX - bounds.left, y: event.clientY - bounds.top};
  }
  function pinchStart() {
    const [first, second] = [...pointers.values()];
    const middle = {x: (first.x + second.x) / 2, y: (first.y + second.y) / 2};
    gesture = {type: "pinch", moved: true, distance: Math.max(1, Math.hypot(second.x - first.x, second.y - first.y)), scale: view.scale,
      anchor: {x: (middle.x - view.x) / view.scale, y: (middle.y - view.y) / view.scale}};
  }
  function cancelGesture() {
    const captured = [...pointers.keys()]; pointers.clear(); gesture = null; dirtyNodes.clear();
    if (pointerFrame !== null) cancelAnimationFrame(pointerFrame);
    pointerFrame = null; graph.removeAttribute("data-dragging"); suppressClickUntil = performance.now() + 450;
    for (const id of captured) { try { graph.releasePointerCapture(id); } catch (_) { /* Already released. */ } }
  }
  graph.addEventListener("pointerdown", event => {
    if (event.pointerType === "mouse" && event.button !== 0) return;
    userAdjustedView = true;
    const point = localPoint(event); pointers.set(event.pointerId, point);
    try { graph.setPointerCapture(event.pointerId); } catch (_) { /* A detached pointer can already be gone. */ }
    if (pointers.size >= 2) { pinchStart(); return; }
    const button = event.target.closest?.("[data-topology-node]");
    const id = button?.dataset.topologyNode;
    if (button) button.focus({preventScroll: true});
    gesture = {type: id ? "node" : "pan", id, selectId: id, start: point, origin: id ? {...positions.get(id)} : {x: view.x, y: view.y}, moved: false};
  });
  graph.addEventListener("pointermove", event => {
    if (!pointers.has(event.pointerId) || !gesture) return;
    const point = localPoint(event); pointers.set(event.pointerId, point);
    if (gesture.type === "pinch" && pointers.size >= 2) {
      const [first, second] = [...pointers.values()];
      view.scale = Math.max(.03, Math.min(3.5, gesture.scale * Math.hypot(second.x - first.x, second.y - first.y) / gesture.distance));
      view.x = (first.x + second.x) / 2 - gesture.anchor.x * view.scale;
      view.y = (first.y + second.y) / 2 - gesture.anchor.y * view.scale;
    } else {
      const dx = point.x - gesture.start.x, dy = point.y - gesture.start.y;
      if (!gesture.moved && Math.hypot(dx, dy) < 6) return;
      gesture.moved = true;
      if (gesture.type === "node") {
        if (!positions.has(gesture.id)) { cancelGesture(); return; }
        positions.set(gesture.id, {x: gesture.origin.x + dx / view.scale, y: gesture.origin.y + dy / view.scale}); dirtyNodes.add(gesture.id);
      } else { view.x = gesture.origin.x + dx; view.y = gesture.origin.y + dy; }
    }
    view.fitted = false; graph.dataset.dragging = "true"; schedulePointers(); event.preventDefault();
  });
  function finishPointer(event, canceled = false) {
    if (!pointers.has(event.pointerId)) return;
    const current = gesture; pointers.delete(event.pointerId);
    try { graph.releasePointerCapture(event.pointerId); } catch (_) { /* Safe after pointer cancellation. */ }
    if (pointerFrame !== null) cancelAnimationFrame(pointerFrame);
    flushPointers();
    if (!canceled && current && !current.moved && current.selectId) load(current.selectId);
    suppressClickUntil = performance.now() + 450;
    if (pointers.size >= 2) pinchStart();
    else if (pointers.size === 1) gesture = {type: "pan", start: [...pointers.values()][0], origin: {x: view.x, y: view.y}, moved: true};
    else { gesture = null; graph.removeAttribute("data-dragging"); }
  }
  graph.addEventListener("pointerup", event => finishPointer(event));
  graph.addEventListener("pointercancel", event => finishPointer(event, true));
  graph.addEventListener("lostpointercapture", event => finishPointer(event, true));
  graph.addEventListener("click", event => {
    const button = event.target.closest?.("[data-topology-node]");
    if (button && (event.detail === 0 || performance.now() > suppressClickUntil)) load(button.dataset.topologyNode);
  });
  graph.addEventListener("wheel", event => {
    event.preventDefault();
    const point = localPoint(event), delta = event.deltaY * (event.deltaMode === 1 ? 16 : 1);
    zoomAt(Math.exp(-Math.max(-250, Math.min(250, delta)) * .003), point.x, point.y);
  }, {passive: false});
  graph.addEventListener("keydown", event => {
    const movement = {ArrowLeft: [-35, 0], ArrowRight: [35, 0], ArrowUp: [0, -35], ArrowDown: [0, 35]}[event.key];
    if (movement) {
      userAdjustedView = true;
      event.preventDefault(); const button = event.target.closest?.("[data-topology-node]");
      if (event.altKey && button) {
        const id = button.dataset.topologyNode, position = positions.get(id);
        positions.set(id, {x: position.x + movement[0] / view.scale, y: position.y + movement[1] / view.scale}); dirtyNodes.add(id); flushPointers();
      } else { view.x += movement[0]; view.y += movement[1]; applyView(); }
      view.fitted = false;
    } else if (["+", "=", "-", "0"].includes(event.key)) {
      event.preventDefault(); userAdjustedView = true; if (event.key === "0") fitAll(); else zoomAt(event.key === "-" ? .8 : 1.25);
    }
  });
  graph.addEventListener("focusin", event => {
    const id = event.target.dataset.topologyNode, position = positions.get(id);
    if (!position || pointers.size || restoringFocus) return;
    const x = position.x * view.scale + view.x, y = position.y * view.scale + view.y;
    if (x < 55 || x > graph.clientWidth - 55 || y < 30 || y > graph.clientHeight - 70) centerNode(id);
  });
  async function load(id, isRefresh = false) {
    if (id === snapshot.selected_id && !isRefresh) {
      if (controller && requestedId !== id) { controller.abort(); generation += 1; controller = null; requestedId = null; refresh.disabled = false; root.removeAttribute("aria-busy"); }
      select.value = snapshot.selected_id;
      displayMode = "relations"; syncModeControls(); renderGraph();
      setStatus(directionHint());
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
      if (!isRefresh) displayMode = "relations";
      renderSelect();
      renderDetails();
      syncModeControls();
      renderGraph();
      const location = new URL(window.location.href);
      location.searchParams.set("node", snapshot.selected_id);
      location.searchParams.delete("format");
      window.history.replaceState(null, "", location.href);
      setStatus(displayMode === "relations" ? directionHint() : `已读取 ${snapshot.selected.name} 的配置关系。在线状态未检测。`);
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
  root.querySelectorAll("[data-topology-enhanced-control]").forEach(control => { control.hidden = false; });
  root.querySelector("[data-topology-submit]").hidden = true;
  const fullDetails = root.querySelector("[data-topology-full-details]");
  if (fullDetails) fullDetails.open = false;
  refresh.hidden = false;
  form.addEventListener("submit", event => { event.preventDefault(); load(select.value); });
  select.addEventListener("change", () => load(select.value));
  refresh.addEventListener("click", () => load(snapshot.selected_id, true));
  function locateMatch(advance = false) {
    const matches = matchingNodes();
    searchIndex = matches.length ? (advance ? searchIndex + 1 : 0) % matches.length : 0;
    updateGraphFacts();
    if (matches.length) centerNode(matches[searchIndex].id, true);
  }
  search.addEventListener("input", () => locateMatch());
  search.addEventListener("keydown", event => { if (event.key === "Enter") { event.preventDefault(); locateMatch(true); } });
  findNext.addEventListener("click", () => locateMatch(true));
  root.querySelectorAll("[data-topology-mode]").forEach(button => button.addEventListener("click", () => setMode(button.dataset.topologyMode)));
  root.querySelectorAll("[data-topology-direction]").forEach(button => button.addEventListener("click", () => {
    direction = button.dataset.topologyDirection;
    syncModeControls(); renderGraph(); setStatus(directionHint());
  }));
  root.querySelector("[data-topology-zoom-in]").addEventListener("click", () => zoomAt(1.25));
  root.querySelector("[data-topology-zoom-out]").addEventListener("click", () => zoomAt(.8));
  root.querySelector("[data-topology-fit]").addEventListener("click", () => { userAdjustedView = true; fitAll(); });
  root.querySelector("[data-topology-reset]").addEventListener("click", () => {
    userAdjustedView = true;
    syncPositions(true);
    for (const id of positions.keys()) dirtyNodes.add(id);
    flushPointers(); fitAll();
  });
  if ("ResizeObserver" in window) new ResizeObserver(scheduleGraph).observe(graph);
  else window.addEventListener("resize", scheduleGraph);
  window.addEventListener("pagehide", () => {
    generation += 1;
    if (controller) controller.abort();
    controller = null;
    requestedId = null;
    if (layoutFrame !== null) cancelAnimationFrame(layoutFrame);
    layoutFrame = null;
    if (pointerFrame !== null) cancelAnimationFrame(pointerFrame);
    flushPointers();
    for (const id of pointers.keys()) { try { graph.releasePointerCapture(id); } catch (_) { /* Already released. */ } }
    pointers.clear(); gesture = null; graph.removeAttribute("data-dragging");
    refresh.disabled = false;
    root.removeAttribute("aria-busy");
    select.value = snapshot.selected_id;
    setStatus(displayMode === "relations" ? directionHint() : "全部节点都在图中。点击节点查看端口。");
  });
  window.addEventListener("pageshow", scheduleGraph);
  renderObservedAt();
  syncModeControls();
  renderGraph();
  scheduleGraph();
})();
