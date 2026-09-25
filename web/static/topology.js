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
  const focus = root.querySelector("[data-topology-focus]");
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
    const ratio = graph.clientWidth / Math.max(1, graph.clientHeight);
    return Math.sqrt(Math.max(.25, Math.min(1.7, ratio < .9 ? ratio * .58 : ratio)));
  }
  function syncPositions(rearrange = false) {
    const ids = new Set(snapshot.nodes.map(node => node.id));
    for (const id of positions.keys()) if (!ids.has(id)) positions.delete(id);
    if (rearrange) positions.clear();
    if (!positions.size) {
      positions.set("hub", {x: 0, y: 0});
      const clients = snapshot.nodes.filter(node => node.id !== "hub");
      const aspect = measuredAspect(); layoutAspect = aspect;
      let offset = 0, ring = 0;
      while (offset < clients.length) {
        const count = Math.min(8 + ring * 6, clients.length - offset);
        const radius = 190 + ring * 175;
        for (let index = 0; index < count; index += 1) {
          const angle = -Math.PI / 2 + index * Math.PI * 2 / count + ring * .3;
          positions.set(clients[offset + index].id, {x: Math.cos(angle) * radius * aspect, y: Math.sin(angle) * radius / aspect});
        }
        offset += count; ring += 1;
      }
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
  function applyView(reflowLabels = false) {
    if (!scene) return;
    scene.world.style.transform = `translate(${view.x}px, ${view.y}px) scale(${view.scale})`;
    scene.world.style.setProperty("--topology-inverse-scale", String(1 / view.scale));
    scene.marker.setAttribute("markerWidth", String(10 / view.scale));
    scene.marker.setAttribute("markerHeight", String(10 / view.scale));
    graph.dataset.viewportX = String(view.x);
    graph.dataset.viewportY = String(view.y);
    graph.dataset.viewportScale = String(view.scale);
    root.querySelector("[data-topology-zoom]").textContent = `${Math.round(view.scale * 100)}%`;
    if (reflowLabels || scene.nodeLabelScale !== view.scale) sizeNodeLabels();
    if (scene.edges.length <= 100 && (reflowLabels || scene.labelScale !== view.scale)) layoutSmallLabels();
  }
  function fitAll() {
    if (!positions.size) return;
    const points = [...positions.values()];
    const xs = points.map(point => point.x), ys = points.map(point => point.y);
    const minX = Math.min(...xs), maxX = Math.max(...xs), minY = Math.min(...ys), maxY = Math.max(...ys);
    view.width = graph.clientWidth; view.height = graph.clientHeight;
    view.scale = Math.max(.03, Math.min(1.4, (view.width - 136) / Math.max(1, maxX - minX), (view.height - 150) / Math.max(1, maxY - minY)));
    view.x = view.width / 2 - (minX + maxX) / 2 * view.scale;
    view.y = (view.height - 24) / 2 - (minY + maxY) / 2 * view.scale;
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
    const from = positions.get(spoke.source), to = positions.get("hub");
    spoke.line.setAttribute("x1", from.x); spoke.line.setAttribute("y1", from.y);
    spoke.line.setAttribute("x2", to.x); spoke.line.setAttribute("y2", to.y);
  }
  function drawLink(edge) {
    const from = positions.get(edge.source), to = positions.get(edge.target);
    const dx = to.x - from.x, dy = to.y - from.y, length = Math.max(1, Math.hypot(dx, dy));
    const bend = edge.paired ? Math.min(70, Math.max(28, length * .16)) : Math.min(30, length * .06);
    const cx = (from.x + to.x) / 2 - dy / length * bend;
    const cy = (from.y + to.y) / 2 + dx / length * bend;
    edge.curve = {from, to, cx, cy};
    edge.path.setAttribute("d", `M ${from.x} ${from.y} Q ${cx} ${cy} ${to.x} ${to.y}`);
    const t = edge.labelPosition, rest = 1 - t;
    const x = rest * rest * from.x + 2 * rest * t * cx + t * t * to.x;
    const y = rest * rest * from.y + 2 * rest * t * cy + t * t * to.y;
    edge.label.setAttribute("transform", `translate(${x} ${y})`);
  }
  function sizeNodeLabels() {
    const points = [...positions].map(([id, position]) => ({id, x: position.x * view.scale, y: position.y * view.scale}));
    for (const point of points) {
      let width = 118;
      for (const other of points) if (point.id !== other.id && Math.abs(point.y - other.y) < 42) width = Math.min(width, Math.max(54, Math.abs(point.x - other.x) - 8));
      const button = scene.nodes.get(point.id);
      button.style.setProperty("--topology-label-width", `${width}px`);
      button.dataset.labelWidth = String(width);
    }
    scene.nodeLabelScale = view.scale;
  }
  function layoutSmallLabels() {
    const occupied = [...positions].map(([id, position]) => {
      const width = Number(scene.nodes.get(id)?.dataset.labelWidth || 118) + 8;
      return {x: position.x * view.scale + view.x - width / 2, y: position.y * view.scale + view.y - 18, width, height: 69};
    });
    const overlap = (one, two) => Math.max(0, Math.min(one.x + one.width, two.x + two.width) - Math.max(one.x, two.x)) *
      Math.max(0, Math.min(one.y + one.height, two.y + two.height) - Math.max(one.y, two.y));
    for (const edge of scene.edges) {
      if (focus.checked && edge.source !== snapshot.selected_id && edge.target !== snapshot.selected_id) continue;
      const {from, to, cx, cy} = edge.curve;
      const dx = to.x - from.x, dy = to.y - from.y, length = Math.max(1, Math.hypot(dx, dy));
      let best = null;
      for (const t of [edge.labelPosition, .5, .3, .7, .18, .82]) {
        const rest = 1 - t;
        const anchorX = (rest * rest * from.x + 2 * rest * t * cx + t * t * to.x) * view.scale + view.x;
        const anchorY = (rest * rest * from.y + 2 * rest * t * cy + t * t * to.y) * view.scale + view.y;
        for (const offset of [0, -20, 20, -40, 40, -65, 65, -88, 88]) {
          const rawX = anchorX - dy / length * offset, rawY = anchorY + dx / length * offset;
          const x = Math.max(edge.labelWidth / 2 + 8, Math.min(graph.clientWidth - edge.labelWidth / 2 - 8, rawX));
          const y = Math.max(edge.labelHeight / 2 + 8, Math.min(graph.clientHeight - edge.labelHeight / 2 - 8, rawY));
          const box = {x: x - edge.labelWidth / 2 - 3, y: y - edge.labelHeight / 2 - 3, width: edge.labelWidth + 6, height: edge.labelHeight + 6};
          const outside = Math.max(0, 5 - box.x) + Math.max(0, box.x + box.width - graph.clientWidth + 5) +
            Math.max(0, 5 - box.y) + Math.max(0, box.y + box.height - graph.clientHeight + 5);
          const score = occupied.reduce((sum, other) => sum + overlap(box, other), 0) * 15 + outside * 80 + Math.abs(offset) + Math.abs(t - .5) * 30 + Math.hypot(x - rawX, y - rawY) * 2;
          if (!best || score < best.score) best = {score, x, y, anchorX, anchorY, box};
        }
      }
      occupied.push(best.box);
      const x = (best.x - view.x) / view.scale, y = (best.y - view.y) / view.scale;
      edge.label.setAttribute("transform", `translate(${x} ${y})`);
      edge.leader.setAttribute("x1", (best.anchorX - view.x) / view.scale); edge.leader.setAttribute("y1", (best.anchorY - view.y) / view.scale);
      edge.leader.setAttribute("x2", x); edge.leader.setAttribute("y2", y);
      edge.leader.style.opacity = Math.hypot(best.x - best.anchorX, best.y - best.anchorY) > 5 ? ".5" : "0";
    }
    scene.labelScale = view.scale;
  }
  function updateGraphFacts() {
    const matched = new Set(matchingNodes().map(node => node.id));
    const relations = new Map(snapshot.relations.map(relation => [relation.node.id, relation]));
    for (const node of snapshot.nodes) {
      const button = scene.nodes.get(node.id), chosen = node.id === snapshot.selected_id;
      const relation = relations.get(node.id);
      button.className = `topology-node kind-${node.kind} availability-${node.availability}${node.kind === "hub" ? " is-hub" : ""}${matched.has(node.id) ? " is-match" : ""}`;
      button.setAttribute("aria-pressed", String(chosen));
      button.setAttribute("aria-label", `${node.name}，${node.kind_label}，${node.state}，在线未检测，${chosen ? "当前观察节点" : relation?.label || "中心网关"}。可拖动调整布局。`);
      button.title = `${node.name} · ${node.address || node.kind_label} · ${node.state} · 在线未检测`;
      button.querySelector("strong").textContent = node.name;
      button.querySelector(".topology-node-state").textContent = node.kind === "hub" ? "中心网关" : `${node.kind.toUpperCase()} · ${node.state}`;
    }
    scene.world.classList.toggle("is-focused", focus.checked);
    let visible = 0;
    for (const edge of scene.edges) {
      const connected = edge.source === snapshot.selected_id || edge.target === snapshot.selected_id;
      edge.group.classList.toggle("is-connected", connected);
      if (!focus.checked || connected) visible += edge.bidirectional ? 2 : 1;
    }
    const matchLabel = search.value.trim() ? ` · 搜索匹配 ${matched.size} 个` : "";
    root.querySelector("[data-topology-canvas-summary]").textContent = `全部 ${snapshot.nodes.length} 个节点（含 VPS） · ${focus.checked ? `聚焦 ${visible} / ` : ""}${snapshot.links.length} 个授权方向${matchLabel}`;
    findNext.disabled = !matched.size;
    if (scene.edges.length <= 100) layoutSmallLabels();
  }
  function renderGraph() {
    if (!graph.clientWidth || !graph.clientHeight) {
      if (layoutFrame !== null) cancelAnimationFrame(layoutFrame);
      layoutFrame = requestAnimationFrame(() => { layoutFrame = null; renderGraph(); });
      return;
    }
    if (gesture?.id && !snapshot.nodes.some(node => node.id === gesture.id)) cancelGesture();
    syncPositions();
    const key = JSON.stringify([snapshot.nodes.map(node => node.id), snapshot.links]);
    if (scene && drawingKey === key) { updateGraphFacts(); return; }
    const focusedId = graph.contains(document.activeElement) ? document.activeElement.dataset.topologyNode : null;
    const world = element("div", "topology-world");
    world.setAttribute("data-topology-world", "");
    const diagram = svgElement("svg", {"aria-hidden": "true", focusable: "false"});
    const marker = svgElement("marker", {id: "topology-arrow", viewBox: "0 0 10 10", refX: 23, refY: 5, markerWidth: 10, markerHeight: 10, markerUnits: "userSpaceOnUse", orient: "auto-start-reverse"});
    marker.append(svgElement("path", {d: "M 1 1 L 8 5 L 1 9", fill: "none", class: "topology-arrow", "stroke-width": 1.5, "stroke-linecap": "round", "stroke-linejoin": "round"}));
    const definitions = svgElement("defs", {}); definitions.append(marker); diagram.append(definitions);
    scene = {world, marker, nodes: new Map(), edges: [], spokes: [], incidents: new Map(snapshot.nodes.map(node => [node.id, new Set()]))};
    for (const node of snapshot.nodes) if (node.id !== "hub") {
      const line = svgElement("line", {class: "topology-spoke", "data-topology-spoke": "", "data-source": node.id, "data-target": "hub"});
      const spoke = {source: node.id, line}; scene.spokes.push(spoke); diagram.append(line); drawSpoke(spoke);
    }
    const byPair = new Map(snapshot.links.map(link => [JSON.stringify([link.source, link.target]), link]));
    const consumed = new Set();
    const nodeNames = new Map(snapshot.nodes.map(node => [node.id, node.name]));
    for (const link of snapshot.links) {
      const pair = JSON.stringify([link.source, link.target]);
      if (consumed.has(pair)) continue;
      consumed.add(pair);
      const reverseKey = JSON.stringify([link.target, link.source]), reverse = byPair.get(reverseKey);
      const bidirectional = Boolean(reverse && link.status === reverse.status && JSON.stringify(link.scopes) === JSON.stringify(reverse.scopes));
      if (bidirectional) consumed.add(reverseKey);
      const linkKey = `${link.source}→${link.target}`;
      const group = svgElement("g", {class: "topology-link", "data-topology-link": "", "data-link-key": linkKey});
      const path = svgElement("path", {class: "topology-edge", "data-topology-edge": "", "data-source": link.source, "data-target": link.target, "data-link-key": linkKey, "data-bidirectional": String(bidirectional), "marker-end": "url(#topology-arrow)"});
      if (bidirectional) path.setAttribute("marker-start", "url(#topology-arrow)");
      const label = svgElement("g", {class: "topology-edge-label", "data-topology-edge-label": "", "data-link-key": linkKey, "data-source": link.source, "data-target": link.target});
      const inner = svgElement("g", {class: "topology-edge-label-inner"});
      const full = `${nodeNames.get(link.source)} ${bidirectional ? "↔" : "→"} ${nodeNames.get(link.target)}：${link.label}`;
      const title = svgElement("title", {}); title.textContent = full;
      const compact = link.label.replaceAll("全部协议 · 全部端口", "全协议 / 全端口").replaceAll(" · ", " ").replaceAll(", ", ",");
      let lines = compact.split("；");
      if (lines.length === 1 && compact.length > 19) {
        const split = compact.lastIndexOf(",", 18);
        if (split > 4) lines = [compact.slice(0, split + 1), compact.slice(split + 1)];
      }
      lines = lines.slice(0, 2).map((line, index) => line.length > 25 ? `${line.slice(0, 23)}…` : line + (index === 1 && compact.split("；").length > 2 ? "…" : ""));
      const labelWidth = Math.max(...lines.map(line => [...line].reduce((sum, char) => sum + (char.charCodeAt(0) > 255 ? 10 : 6.05), 14)));
      const labelHeight = lines.length * 13 + 8;
      const rectangle = svgElement("rect", {x: -labelWidth / 2, y: -labelHeight / 2, width: labelWidth, height: labelHeight, rx: 4});
      const text = svgElement("text", {class: "topology-edge-text", x: 0});
      lines.forEach((line, index) => { const span = svgElement("tspan", {x: 0, y: (index - (lines.length - 1) / 2) * 13 + .5}); span.textContent = line; text.append(span); });
      const leader = svgElement("line", {class: "topology-label-leader"});
      label.setAttribute("aria-label", full); inner.append(rectangle, text); label.append(title, inner); group.append(path, leader, label); diagram.append(group);
      let hash = 0; for (const char of linkKey) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
      const edge = {...link, group, path, label, leader, labelWidth, labelHeight, bidirectional, paired: Boolean(reverse && !bidirectional), labelPosition: .36 + (hash % 5) * .07};
      scene.edges.push(edge); scene.incidents.get(link.source).add(edge); scene.incidents.get(link.target).add(edge); drawLink(edge);
    }
    world.append(diagram);
    for (const node of snapshot.nodes) {
      const button = element("button", "topology-node"); button.type = "button"; button.dataset.topologyNode = node.id;
      const dot = element("span", "topology-node-dot"); dot.setAttribute("aria-hidden", "true");
      button.append(dot, element("strong", "", node.name), element("span", "topology-node-state"));
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
    const reflowLabels = dirtyNodes.size > 0;
    dirtyNodes.clear(); applyView(reflowLabels);
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
      else { view.x += (width - view.width) / 2; view.y += (height - view.height) / 2; view.width = width; view.height = height; applyView(); }
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
    const label = event.target.closest?.("[data-topology-edge-label]");
    const id = button?.dataset.topologyNode;
    if (button) button.focus({preventScroll: true});
    gesture = {type: id ? "node" : "pan", id, selectId: id || label?.dataset.source, start: point, origin: id ? {...positions.get(id)} : {x: view.x, y: view.y}, moved: false};
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
  function locateMatch(advance = false) {
    const matches = matchingNodes();
    searchIndex = matches.length ? (advance ? searchIndex + 1 : 0) % matches.length : 0;
    updateGraphFacts();
    if (matches.length) centerNode(matches[searchIndex].id, true);
  }
  search.addEventListener("input", () => locateMatch());
  search.addEventListener("keydown", event => { if (event.key === "Enter") { event.preventDefault(); locateMatch(true); } });
  findNext.addEventListener("click", () => locateMatch(true));
  focus.addEventListener("change", updateGraphFacts);
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
    setStatus(`当前观察：${snapshot.selected.name}。在线状态未检测。`);
  });
  window.addEventListener("pageshow", scheduleGraph);
  renderObservedAt();
  renderGraph();
  scheduleGraph();
})();
