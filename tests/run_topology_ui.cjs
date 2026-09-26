"use strict";

// Isolated browser regression with synthetic fixtures only; never targets a VPS.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {chromium, webkit} = require("playwright");
const {assertCardEdges, assertInlinePorts, geometryFindings, inlineSnapshot} = require("./topology_inline_assertions.cjs");
const base = new URL(process.argv[2] || "http://127.0.0.1:8765/");
if (base.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(base.hostname)
    || base.username || base.password || base.pathname !== "/") throw new Error("Only an isolated loopback preview is allowed.");
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "server-kit-topology-"));
console.log(`Topology QA started: ${directory}`);
const report = {directory, checks: [], screenshots: [], errors: [], blocked: [], performance: [], controlStyles: [], readability: []};
const password = "Preview-only-2026!";
const topologyURL = new URL("network/topology/", base).href;
const hook = (page, name) => page.locator(`[data-topology-${name}]`);
const jsonRoute = url => url.origin === base.origin && url.pathname === "/network/topology/" && url.searchParams.get("format") === "json";
const jsonResponse = response => jsonRoute(new URL(response.url()));
// Tall element captures can composite an offscreen fixed skip link into the
// middle of the image. Hide only that unfocused, already-offscreen link during
// capture; it remains available and unchanged in every interaction test.
const captureStyle = ".skip-link:not(:focus) { visibility: hidden !important; }";

function syntheticModel(original, id = "hub", revision = "") {
  const hub = {...original.nodes.find(node => node.id === "hub")};
  const source = original.nodes.find(node => node.kind === "awg");
  assert.ok(source, "rich fixture must contain an AWG node");
  const nodes = [hub, ...Array.from({length: 40}, (_, index) => {
    const name = `synthetic-${String(index).padStart(2, "0")}${index === 39 ? "-long-node-name-for-mobile-layout" : ""}`;
    return {...source, id: `awg:${name}`, name: name + revision, address: `10.20.1.${index + 10}`, protected: false};
  })];
  const selected = nodes.find(node => node.id === id) || hub;
  const allowed = {status: "partial", label: "指定范围", summary: "TCP 22,443", scopes: ["TCP 22,443"], warnings: []};
  const unknown = {status: "unknown", label: "未检测", summary: "VPS 发起的访问未检测", scopes: [], warnings: []};
  const links = nodes.filter(node => node.kind !== "hub").flatMap(source => nodes.filter(target => target.id !== source.id)
    .map(target => ({source: source.id, target: target.id, status: "partial", label: "TCP 22,443", scopes: ["TCP 22,443"]})));
  return {...original, nodes, selected, selected_id: selected.id,
    links,
    relations: nodes.filter(node => node.id !== selected.id).map(node => ({node,
      forward: {...(selected.kind === "hub" ? unknown : allowed)}, reverse: {...(node.kind === "hub" ? unknown : allowed)},
      relation: selected.kind === "hub" ? "inbound" : node.kind === "hub" ? "outbound" : "mutual", label: "配置授权"})),
    summary: {nodes: 40, awg: 40, vless: 0, enabled: 40, disabled: 0, pending: 0},
    observed_at: new Date().toISOString()};
}

function realisticModel(original, id, scopeOverride = null) {
  const hub = {...original.nodes.find(node => node.id === "hub")};
  const template = original.nodes.find(node => node.kind === "awg");
  const names = ["home-desktop", "office-workstation", "nas-primary", "nas-backup", "lab-server", "travel-laptop", "media-server", "family-desktop", "iphone-travel", "android-daily", "retired-phone"];
  const nodes = [hub, ...names.map((name, index) => {
    const kind = index < 8 ? "awg" : "vless", disabled = index === 10;
    return {...template, id: `${kind}:${name}`, name, kind, kind_label: kind === "awg" ? "AmneziaWG" : "VLESS",
      address: kind === "awg" ? `10.20.2.${index + 10}` : "", protected: index === 0,
      availability: disabled ? "disabled" : "enabled", state: disabled ? "已禁用" : "已启用"};
  })];
  const scopes = scopeOverride ? [scopeOverride] : [["全部协议 · 全部端口"], ["TCP · 22, 443"], ["UDP · 53"], ["TCP · 8000-8010"]];
  const targets = nodes.filter(node => node.kind !== "vless");
  const sources = nodes.filter(node => node.kind !== "hub" && node.availability === "enabled");
  const links = [];
  for (let offset = 0; links.length < 46 && offset < targets.length; offset++) {
    for (let index = 0; index < sources.length && links.length < 46; index++) {
      const source = sources[index], target = targets[(index + offset) % targets.length];
      if (source.id === target.id) continue;
      const allowedScopes = scopes[(index + offset) % scopes.length];
      links.push({source: source.id, target: target.id, status: !scopeOverride && allowedScopes === scopes[0] ? "allowed" : "partial", label: allowedScopes.join("；"), scopes: allowedScopes});
    }
  }
  const selected = nodes.find(node => node.id === id) || nodes[1];
  function access(from, to) {
    const link = links.find(link => link.source === from.id && link.target === to.id);
    if (link) return {status: link.status, label: "配置授权", summary: link.label, scopes: link.scopes, warnings: []};
    const status = from.kind === "hub" ? "unknown" : to.kind === "vless" ? "not_applicable" : from.availability === "disabled" || to.availability === "disabled" ? "inactive" : "denied";
    return {status, label: status === "unknown" ? "未检测" : status === "inactive" ? "已禁用" : status === "not_applicable" ? "不适用" : "未授权", summary: "没有确认可用的配置授权", scopes: [], warnings: []};
  }
  const relations = nodes.filter(node => node.id !== selected.id).map(node => {
    const forward = access(selected, node), reverse = access(node, selected);
    const outbound = ["allowed", "partial"].includes(forward.status), inbound = ["allowed", "partial"].includes(reverse.status);
    return {node, forward, reverse, relation: outbound && inbound ? "mutual" : outbound ? "outbound" : inbound ? "inbound" : "unknown", label: "配置访问关系"};
  });
  return {...original, nodes, selected, selected_id: selected.id, links, relations,
    summary: {nodes: 11, awg: 8, vless: 3, enabled: 10, disabled: 1, pending: 0}, observed_at: new Date().toISOString()};
}

async function session(browser, width = 390, options = {}) {
  const context = await browser.newContext({viewport: {width, height: width < 768 ? 844 : 1000},
    ...(width < 768 ? {isMobile: true, hasTouch: true} : {}), ...options});
  await context.route("**/*", route => {
    if (new URL(route.request().url()).origin === base.origin) return route.continue();
    report.blocked.push(route.request().url());
    return route.abort();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  page.on("pageerror", error => report.errors.push(error.message));
  await page.goto(new URL("login/", base).href);
  await page.locator('[name="username"]').fill("preview");
  await page.locator('[name="password"]').fill(password);
  await Promise.all([page.waitForURL(base.href), page.locator('button[type="submit"]').click()]);
  assert.equal((await context.request.get(new URL("__preview__/scenario/rich/", base).href)).status(), 200);
  const navigations = [], requests = [], allRequests = [];
  page.on("request", request => {
    const item = {url: request.url(), method: request.method()};
    allRequests.push(item);
    if (jsonRoute(new URL(item.url))) requests.push(item);
    if (request.isNavigationRequest() && request.frame() === page.mainFrame()) navigations.push(request.url());
  });
  await page.goto(topologyURL);
  await hook(page, "root").waitFor();
  navigations.length = 0;
  return {context, page, navigations, requests, allRequests};
}

async function screenshot(page, label) {
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true, `${label}: page overflow`);
  await page.evaluate(() => document.activeElement?.blur());
  await page.screenshot({path: path.join(directory, `${label}.png`), fullPage: true, style: captureStyle});
  report.screenshots.push(`${label}.png`);
}

async function choose(page, id) {
  // Native selection is available at every zoom and pan position.
  await hook(page, "select").selectOption(id);
}

async function openViewTools(page) {
  if (!await hook(page, "view-options").evaluate(details => details.open)) await hook(page, "view-options").locator("summary").click();
}

async function closeViewTools(page) {
  if (await hook(page, "view-options").evaluate(details => details.open)) await hook(page, "view-options").locator("summary").click();
}

async function mode(page, name) {
  await page.locator(`button[data-topology-mode="${name}"]`).click();
  await settleGraph(page);
}

async function direction(page, name) {
  await page.locator(`[data-topology-direction="${name}"]`).click();
  await settleGraph(page);
}

async function selectionSettled(page, id) {
  // A fresh selection can be a local 30-second cache hit. Check the applied
  // model, not merely the native select value (which changes before a fetch).
  await page.waitForFunction(id => {
    const root = document.querySelector("[data-topology-root]");
    return !root.hasAttribute("aria-busy") && document.querySelector("[data-topology-select]").value === id
      && root.querySelector('[data-topology-node][aria-pressed="true"]')?.dataset.topologyNode === id
      && root.querySelector('[data-topology-mode="relations"]').getAttribute("aria-pressed") === "true"
      && document.querySelector("[data-topology-status]").dataset.state !== "error";
  }, id);
  await settleGraph(page);
}

async function selectAndWait(page, id) {
  await choose(page, id);
  await selectionSettled(page, id);
}

async function assertGraph(page, expectedLinks = null) {
  // Read geometry and metadata atomically while pointer movement can redraw.
  const value = await hook(page, "graph").evaluate(graph => {
    const nodeElements = [...graph.querySelectorAll("[data-topology-node]")];
    const edgeElements = [...graph.querySelectorAll("[data-topology-edge]")].filter(edge => getComputedStyle(edge.closest("[data-topology-link]") || edge).display !== "none");
    const nodes = nodeElements.map(node => ({id: node.dataset.topologyNode, tag: node.tagName, pressed: node.getAttribute("aria-pressed"),
      peer: node.dataset.topologyPeer || null, classPeer: node.classList.contains("is-peer"), related: node.classList.contains("is-related"),
      x: Number(node.dataset.worldX), y: Number(node.dataset.worldY)}));
    const selectedId = document.querySelector("[data-topology-select]").value;
    const edges = edgeElements.map(edge => ({tag: edge.tagName.toLowerCase(), source: edge.dataset.source, target: edge.dataset.target,
      key: edge.dataset.linkKey, dash: getComputedStyle(edge).strokeDasharray, marker: edge.getAttribute("marker-end"),
      reverseMarker: edge.getAttribute("marker-start"), bidirectional: edge.dataset.bidirectional === "true"}));
    const spokes = [...graph.querySelectorAll("[data-topology-spoke]")].filter(line => getComputedStyle(line).display !== "none").map(line => ({source: line.dataset.source, target: line.dataset.target, dash: getComputedStyle(line).strokeDasharray}));
    return {nodes, selectedId, edges, spokes, options: document.querySelector("[data-topology-select]").options.length,
      initialLinks: JSON.parse(document.getElementById("topology-data").textContent).links,
      mode: document.querySelector('[data-topology-mode][aria-pressed="true"]')?.dataset.topologyMode,
      direction: document.querySelector('[data-topology-direction][aria-pressed="true"]')?.dataset.topologyDirection};
  });
  const {nodes, selectedId, edges, spokes} = value;
  assert.equal(nodes.filter(node => node.id === "hub").length, 1, "one central VPS");
  assert.ok(nodes.every(node => node.tag === "BUTTON"), "graph nodes are keyboard-operable buttons");
  assert.equal(nodes.length, value.options, "every configured node exists in the graph at once");
  assert.ok(nodes.every(node => Number.isFinite(node.x) && Number.isFinite(node.y)), "nodes expose finite layout coordinates");
  assert.equal(nodes.filter(node => node.pressed === "true").length, 1, "one selected node remains present at every zoom");
  assert.ok(["overview", "relations"].includes(value.mode), "one graph mode is selected");
  assert.ok(["forward", "reverse"].includes(value.direction), "one relationship direction is selected");
  assert.equal(spokes.length, nodes.length - 1, "every graph mode preserves one structural hub spoke per client");
  const ids = new Set(nodes.map(node => node.id));
  for (const line of spokes) {
    assert.ok((line.source === "hub") !== (line.target === "hub"), "structural spokes preserve the complete VPS star without client-to-client lines");
    assert.ok(ids.has(line.source) && ids.has(line.target));
    assert.ok(line.dash && line.dash !== "none" && line.dash !== "0px", "VPS access spokes are dashed");
  }
  const expected = value.mode === "overview" ? [] : (expectedLinks || value.initialLinks).filter(link =>
    value.direction === "forward" ? link.source === selectedId : link.target === selectedId);
  const drawn = expected.filter(link => link.source === "hub" || link.target === "hub");
  const directions = edges.flatMap(edge => edge.bidirectional ? [[edge.source, edge.target].join("→"), [edge.target, edge.source].join("→")] : [[edge.source, edge.target].join("→")]);
  assert.deepEqual(directions.sort(), drawn.map(edge => [edge.source, edge.target].join("→")).sort(),
    "only confirmed selected-direction permissions involving the VPS have arrows; leaf-to-leaf paths are not mounted");
  const peers = expected.map(link => value.direction === "forward" ? link.target : link.source).sort();
  assert.deepEqual(nodes.filter(node => node.classPeer).map(node => node.id).sort(), peers,
    "leaf-to-leaf permissions still receive peer frames even though their crossing paths are absent");
  assert.deepEqual(nodes.filter(node => node.peer).map(node => node.id).sort(), peers);
  assert.ok(nodes.filter(node => node.peer).every(node => node.peer === (value.direction === "forward" ? "outbound" : "inbound")));
  assert.deepEqual(nodes.filter(node => node.related).map(node => node.id).sort(), [...new Set(expected.flatMap(link => [link.source, link.target]))].sort(),
    "related-node highlighting uses all selected permissions, not just the remaining VPS arrows");
  if (value.mode === "relations") assert.match(await hook(page, "canvas-summary").innerText(), new RegExp(`当前方向 ${expected.length} 条授权`),
    "the canvas counts every authorization, including invisible leaf-to-leaf paths");
  await assertInlinePorts(page, expectedLinks || value.initialLinks, selectedId, value.direction, value.mode === "overview");
  for (const edge of edges) {
    assert.equal(edge.tag, "path");
    assert.ok(edge.dash && edge.dash !== "none" && edge.dash !== "0px", "permission links are dashed");
    assert.ok(edge.marker, "every permission path has a directional arrow");
    assert.ok(edge.source === "hub" || edge.target === "hub", "no leaf-to-leaf permission path survives");
    assert.equal(edge.bidirectional, false, "a single-direction inspection must not imply a reverse permission");
    const link = expected.find(link => link.source === edge.source && link.target === edge.target);
    assert.ok(link, "every drawn edge exists in the configured selected direction");
  }
  assert.equal(await hook(page, "direction").first().isVisible(), value.mode === "relations", "direction control is shown only while inspecting relationships");
  assert.equal(await hook(page, "focus").count(), 0, "the old all-edge focus checkbox is removed");
  assert.equal(await page.locator("[data-topology-prev], [data-topology-next], [data-topology-page]").count(), 0, "graph has no pagination");
  if (value.mode === "relations") {
    const inspector = hook(page, "inspector");
    assert.equal(await inspector.evaluate(node => node.tagName), "ASIDE", "inspector is an accessible complementary region");
    assert.equal(await inspector.isVisible(), true);
    const contents = await inspector.innerText();
    for (const link of expected) for (const scope of link.scopes) assert.ok(contents.includes(scope), "inspector preserves every exact configured protocol/port scope");
    const rows = await inspector.locator("[data-topology-access-target]").evaluateAll(items => items.map(item => ({id: item.dataset.topologyAccessTarget,
      scopes: [...item.querySelectorAll(".topology-access-scopes li")].map(scope => scope.textContent)})));
    assert.deepEqual(rows.sort((a, b) => a.id.localeCompare(b.id)), expected.map(link => ({id: value.direction === "forward" ? link.target : link.source, scopes: link.scopes})).sort((a, b) => a.id.localeCompare(b.id)),
      "inspector contains only the correct endpoint and complete exact scopes for the selected direction");
  }
}

async function assertReadOnly(session) {
  assert.deepEqual(session.navigations, [], "graph interaction must not navigate");
  assert.ok(session.allRequests.every(request => request.method === "GET"), "topology and live telemetry only send read-only GET requests");
  const contents = await hook(session.page, "root").innerHTML();
  assert.doesNotMatch(contents, /synthetic-preview-exit-secret|Preview-only-2026|BEGIN (?:RSA |OPENSSH )?PRIVATE KEY|vless:\/\//);
  const storage = await session.page.evaluate(() => JSON.stringify({local: {...localStorage}, session: {...sessionStorage}}));
  assert.doesNotMatch(storage, /synthetic-preview-exit-secret|Preview-only-2026/);
}

async function viewState(page) {
  return {
    selected: await hook(page, "select").inputValue(),
    options: await hook(page, "select").locator("option").allTextContents(),
    // Live rate/state text is allowed to update while the configuration model
    // stays unchanged. Strip only those separately tested telemetry spans.
    nodes: await hook(page, "node").evaluateAll(nodes => nodes.map(node => { const clone = node.cloneNode(true); clone.querySelectorAll("[data-telemetry-status], [data-telemetry-rates]").forEach(item => item.remove()); return clone.textContent; })),
    details: await hook(page, "details").evaluate(node => { const clone = node.cloneNode(true); clone.querySelectorAll("[data-telemetry-status], [data-telemetry-rates]").forEach(item => item.remove()); return clone.textContent; }),
    inspector: await hook(page, "inspector").textContent(),
    mode: await page.locator('[data-topology-mode][aria-pressed="true"]').getAttribute("data-topology-mode"),
    direction: await page.locator('[data-topology-direction][aria-pressed="true"]').getAttribute("data-topology-direction"),
    graph: await layoutState(page),
  };
}

async function layoutState(page) {
  return hook(page, "graph").evaluate(graph => ({
    positions: [...graph.querySelectorAll("[data-topology-node]")].map(node => ({id: node.dataset.topologyNode,
      x: Number(node.dataset.worldX), y: Number(node.dataset.worldY)})),
    viewport: {x: Number(graph.dataset.viewportX), y: Number(graph.dataset.viewportY), scale: Number(graph.dataset.viewportScale)},
    edges: [...graph.querySelectorAll("[data-topology-edge]")].map(edge => ({key: edge.dataset.linkKey, path: edge.getAttribute("d")})),
    spokes: [...graph.querySelectorAll("[data-topology-spoke]")].map(spoke => ({source: spoke.dataset.source, target: spoke.dataset.target,
      x1: spoke.getAttribute("x1"), y1: spoke.getAttribute("y1"), x2: spoke.getAttribute("x2"), y2: spoke.getAttribute("y2")})),
    ports: [...graph.querySelectorAll(".topology-node-port")].map(port => ({id: port.closest("[data-topology-node]").dataset.topologyNode,
      scope: port.dataset.topologyScope, text: port.textContent})),
  }));
}

async function settleGraph(page) {
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
}

async function readabilitySnapshot(page) {
  const inline = await inlineSnapshot(page);
  const metrics = await hook(page, "graph").evaluate(graph => {
    const canvas = graph.getBoundingClientRect();
    const visible = node => node.getClientRects().length && getComputedStyle(node.closest("[data-topology-link]") || node).display !== "none";
    const names = [...graph.querySelectorAll("[data-topology-node] strong")].map(node => ({text: node.textContent, rect: node.getBoundingClientRect(), font: parseFloat(getComputedStyle(node).fontSize)}));
    const area = (a, b) => Math.max(0, Math.min(a.right, b.right) - Math.max(a.left, b.left)) * Math.max(0, Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top));
    return {nodes: names.length, displayedPermissionPaths: [...graph.querySelectorAll("[data-topology-edge]")].filter(visible).length,
      namesOverlapping: names.flatMap((a, i) => names.slice(i + 1).filter(b => area(a.rect, b.rect) > 4).map(b => [a.text, b.text])),
      nodeNameFont: Math.min(...names.map(node => node.font)),
      canvasTopAtPageStart: Math.round(canvas.top + scrollY), canvasHeight: Math.round(canvas.height), viewportHeight: innerHeight,
      controlsAboveCanvas: [...document.querySelectorAll("[data-topology-root] button, [data-topology-root] input, [data-topology-root] select")]
        .filter(node => node.getClientRects().length && !node.closest("details:not([open])") && node.getBoundingClientRect().bottom <= canvas.top).length};
  });
  const lines = inline.nodes.flatMap(node => node.ports.lines);
  return {...metrics, geometryFindings: geometryFindings(inline), floatingLabels: inline.floating,
    inlinePortFont: lines.length ? Math.min(...lines.map(line => line.font)) : null};
}

async function setTheme(page, width, theme) {
  if (width <= 900) await page.locator("[data-mobile-menu] > summary").click();
  await page.locator(`[data-theme-value="${theme}"]:visible`).first().click();
  if (width <= 900) await page.locator("[data-mobile-menu-close]").click();
  assert.equal(await page.locator("html").getAttribute("data-theme"), theme);
}

async function readabilityAudit(browser, label) {
  for (const width of [320, 390, 768, 1440]) {
    const state = await session(browser, width);
    const {page, context} = state;
    try {
      const original = await (await context.request.get(topologyURL + "?format=json")).json();
      for (const count of [6, 12]) {
        let model = original;
        if (count === 12) {
          model = realisticModel(original);
          assert.equal(model.nodes.length, 12);
          assert.equal(model.links.length, 46, "realistic scene reproduces twelve nodes and forty-six directed permissions");
          await page.route(jsonRoute, route => {
            const id = new URL(route.request().url()).searchParams.get("node");
            return route.fulfill({status: 200, contentType: "application/json", body: JSON.stringify(realisticModel(original, id))});
          });
          await mode(page, "overview");
          await Promise.all([page.waitForResponse(jsonResponse), hook(page, "refresh").click()]);
          await page.waitForFunction(() => document.querySelectorAll("[data-topology-node]").length === 12);
          await openViewTools(page);
          await hook(page, "reset").click();
          await hook(page, "view-options").locator("summary").click();
        }
        await settleGraph(page);
        await mode(page, "overview");
        await assertGraph(page, model.links);
        const selected = await hook(page, "select").inputValue();
        const before = await layoutState(page), requestsBefore = state.requests.length;
        // The initial selection is still an actionable node, even without an RPC.
        await page.locator(`[data-topology-node="${selected}"]`).click();
        await settleGraph(page);
        assert.equal(await page.locator('button[data-topology-mode="relations"]').getAttribute("aria-pressed"), "true", "clicking an already selected node enters relationships");
        assert.equal(state.requests.length, requestsBefore, "already-selected inspection is local");
        await mode(page, "overview");
        assert.deepEqual((await layoutState(page)).positions, before.positions, "mode switch does not rearrange nodes");
        assert.deepEqual((await layoutState(page)).viewport, before.viewport, "mode switch does not move the camera");
        assert.equal(await hook(page, "select").inputValue(), selected, "returning to overview preserves selection");
        assert.equal(state.requests.length, requestsBefore, "overview return needs no fetch");
        const target = model.nodes.find(node => node.kind === "awg" && model.links.some(link => link.source === node.id && link.target !== "hub"));
        assert.ok(target, "readability scene includes client-to-client permissions");
        for (const theme of ["light", "dark", "sky"]) {
          await setTheme(page, width, theme);
          for (const stateName of ["overview", "forward", "reverse"]) {
            if (stateName === "overview") await mode(page, "overview");
            else {
              await selectAndWait(page, target.id);
              await direction(page, stateName);
            }
            await assertGraph(page, model.links);
            await settleGraph(page);
            const metrics = await readabilitySnapshot(page);
            report.readability.push({browser: label, width, theme, state: stateName, configuredDirections: model.links.length, ...metrics});
            const name = `${label}-${width}-${count}-node-${stateName}-${theme}.png`;
            await page.evaluate(() => document.activeElement?.blur());
            await page.locator(".topology-panel").screenshot({path: path.join(directory, name), style: captureStyle});
            report.screenshots.push(name);
            assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true, "realistic topology never overflows the page horizontally");
            assert.deepEqual(metrics.geometryFindings, [], `${name}: fitted cards never overlap or clip and inline ports remain within their own rows`);
            await assertCardEdges(page);
            assert.equal(metrics.floatingLabels, 0);
            assert.deepEqual(metrics.namesOverlapping, [], `${name}: node names must not overlap`);
            assert.ok(metrics.nodeNameFont >= 13, `${name}: node names must be at least 13px, not tiny diagram captions`);
            if (metrics.inlinePortFont !== null) assert.ok(metrics.inlinePortFont >= 12, `${name}: inline protocol/port text must be at least 12px`);
            if (stateName === "overview") {
              assert.equal(metrics.displayedPermissionPaths, 0);
              assert.ok(metrics.controlsAboveCanvas <= (width < 768 ? 6 : 5), "default overview keeps secondary controls closed; touch devices additionally retain the explicit layout-mode escape control");
              if (width <= 390) assert.ok(metrics.canvasTopAtPageStart < 700, "mobile overview exposes the canvas in the first viewport");
            } else {
              const scopeMetrics = await page.locator(".topology-access-scopes li").evaluateAll(items => items.map(item => ({font: parseFloat(getComputedStyle(item).fontSize), overflow: item.scrollWidth > item.clientWidth + 1})));
              const configured = model.links.filter(link => stateName === "forward" ? link.source === target.id : link.target === target.id);
              assert.equal(scopeMetrics.length, configured.reduce((total, link) => total + link.scopes.length, 0), "inspector shows exactly the complete scope entries for this permitted direction");
              assert.ok(scopeMetrics.every(scope => scope.font >= 13 && !scope.overflow), "inspector scopes are readable and wrap within the available width");
            }
          }
        }
        const beforeDirectionChange = state.requests.length;
        await direction(page, "reverse");
        await selectAndWait(page, "hub");
        assert.equal(await page.locator('[data-topology-direction="reverse"]').getAttribute("aria-pressed"), "true", "changing selection preserves the user's chosen direction");
        assert.ok(state.requests.length <= beforeDirectionChange + 1, "direction changes are local; only selection may fetch");
      }
      await assertReadOnly(state);
      report.checks.push(`${label} ${width}: six-node and realistic twelve-node/46-direction scenes, overview and both selected directions, complete inspector, readable type and collision-free inline ports in three themes`);
    } finally { await context.close(); }
  }
}

async function layerSmoke(browser, label) {
  // Keep the historic --layer-smoke entry point while checking the new design.
  for (const width of [320, 1440]) await inlineScopeScenario(browser, label, width);
}

async function inlineScopeScenario(browser, label, width) {
  const state = await session(browser, width);
  const {page, context} = state;
  try {
    const original = await (await context.request.get(topologyURL + "?format=json")).json();
    // A UI-only fixture covers future multi-scope responses, independent of the
    // real backend projection checked by run_topology_permissions_ui.cjs.
    const scopes = ["TCP · 22, 443, 445, 8000-8010, 9000-9090, 10000-11000", "UDP · 53, 123", "ICMP · 全部端口", "TCP · 22000-24000"];
    const model = realisticModel(original, undefined, scopes);
    await page.route(jsonRoute, route => route.fulfill({status: 200, contentType: "application/json",
      body: JSON.stringify(realisticModel(original, new URL(route.request().url()).searchParams.get("node"), scopes))}));
    await Promise.all([page.waitForResponse(jsonResponse), hook(page, "refresh").click()]);
    await page.waitForFunction(() => document.querySelectorAll("[data-topology-node]").length === 12);
    await openViewTools(page);
    await hook(page, "reset").click();
    await closeViewTools(page);
    await selectAndWait(page, model.nodes[1].id);
    await direction(page, "forward");
    await setTheme(page, width, "light");
    await assertGraph(page, model.links);
    const inline = await inlineSnapshot(page);
    assert.ok(inline.nodes.some(node => node.ports.lines.some(line => line.clipped)), "long scopes exercise genuine visual ellipsis while retaining complete DOM/title/aria text");
    assert.ok(inline.nodes.some(node => node.ports.more.visible && /另 2 项/.test(node.ports.more.text)), "the additional-scope count is visible inside the card");
    const metrics = await readabilitySnapshot(page);
    assert.deepEqual(metrics.geometryFindings, []);
    await assertCardEdges(page);
    report.readability.push({browser: label, width, state: "four-inline-scopes", ...metrics});
    await page.evaluate(() => document.activeElement?.blur());
    const name = `${label}-${width}-12-node-four-inline-scopes.png`;
    await page.locator(".topology-panel").screenshot({path: path.join(directory, name), style: captureStyle});
    report.screenshots.push(name);
    await direction(page, "reverse");
    await assertGraph(page, model.links);
    assert.deepEqual((await readabilitySnapshot(page)).geometryFindings, []);
    await mode(page, "overview");
    await assertGraph(page, model.links);
    await assertReadOnly(state);
    report.checks.push(`${label} ${width}: twelve-node inline ports retain four full scopes in DOM/title/aria/inspector, ellipsis and extra-count rows never collide, direction and overview clean up ports`);
  } finally { await context.close(); }
}

async function assertLegibleOverview(page, width) {
  await settleGraph(page);
  const inline = await inlineSnapshot(page);
  assert.equal(inline.floating, 0);
  assert.deepEqual(geometryFindings(inline), [], "fitted card contents and neighboring cards never overlap or clip");
  const result = await hook(page, "graph").evaluate(graph => {
    const box = graph.getBoundingClientRect();
    const names = [...graph.querySelectorAll("[data-topology-node] strong")].map(node => ({name: node.textContent, box: node.getBoundingClientRect()}));
    const nodes = [...graph.querySelectorAll("[data-topology-node]")].map(node => node.getBoundingClientRect());
    const overlap = (a, b) => a.left < b.right - .5 && a.right > b.left + .5 && a.top < b.bottom - .5 && a.bottom > b.top + .5;
    return {
      overlappingNames: names.flatMap((a, index) => names.slice(index + 1).filter(b => overlap(a.box, b.box)).map(b => [a.name, b.name])),
      verticalFraction: (Math.max(...nodes.map(node => node.y + node.height / 2)) - Math.min(...nodes.map(node => node.y + node.height / 2))) / box.height,
    };
  });
  assert.deepEqual(result.overlappingNames, [], "default overview does not obscure node names with neighboring cards");
  if (width <= 390) assert.ok(result.verticalFraction > .5, "cold mobile layout uses the available portrait canvas instead of shrinking a desktop layout");
}

async function assertControlContrast(page, label, width, theme) {
  const styles = await page.evaluate(async () => {
    const buttons = [...document.querySelectorAll(".topology-content button.secondary-button")].filter(button => button.getClientRects().length && !button.closest("details:not([open])"));
    await Promise.race([
      Promise.all(buttons.flatMap(button => button.getAnimations()).map(animation => animation.finished.catch(() => {}))),
      new Promise(resolve => setTimeout(resolve, 500)),
    ]);
    const rgba = color => { const values = color.match(/[\d.]+/g).map(Number); return [...values.slice(0, 3), values[3] ?? 1]; };
    const composite = (front, back) => front.slice(0, 3).map((value, index) => value * front[3] + back[index] * (1 - front[3]));
    const background = element => {
      const layers = [];
      for (let node = element; node; node = node.parentElement) layers.unshift(rgba(getComputedStyle(node).backgroundColor));
      return layers.reduce((color, layer) => composite(layer, color), [255, 255, 255]);
    };
    const luminance = color => {
      const rgb = color.map(value => {
        const channel = value / 255;
        return channel <= .04045 ? channel / 12.92 : ((channel + .055) / 1.055) ** 2.4;
      });
      return rgb[0] * .2126 + rgb[1] * .7152 + rgb[2] * .0722;
    };
    return buttons.map(button => {
      const style = getComputedStyle(button);
      // Selected mode buttons use translucent theme fills; contrast is measured
      // against the composited panel, not the opaque RGB channels of that tint.
      const effectiveBackground = background(button);
      const backgroundLum = luminance(effectiveBackground), foregroundLum = luminance(composite(rgba(style.color), effectiveBackground));
      return {text: button.textContent.trim(), disabled: button.disabled, background: style.backgroundColor, color: style.color,
        effectiveBackground,
        appearance: style.appearance, webkitAppearance: style.webkitAppearance, image: style.backgroundImage,
        backgroundLum, contrast: (Math.max(backgroundLum, foregroundLum) + .05) / (Math.min(backgroundLum, foregroundLum) + .05)};
    });
  });
  assert.ok(styles.length >= 3, "primary topology controls expose themed buttons");
  for (const style of styles) {
    assert.equal(style.appearance, "none", `${label} ${theme} ${style.text}: native appearance must not override the themed background`);
    assert.equal(style.image, "none", `${label} ${theme} ${style.text}: no native background image`);
    if (!style.disabled) assert.ok(style.contrast >= 4.5, `${label} ${theme} ${style.text}: text/background contrast ${style.contrast.toFixed(2)} is too low`);
    if (theme === "dark") assert.ok(style.backgroundLum < .2, `${label}: dark controls must not render a light fill`);
  }
  if (width === 1440) report.controlStyles.push({browser: label, theme, buttons: styles});
}

async function coldMobileLayouts(browser, label) {
  for (const [attempt, options] of [[0, {}], [1, {isMobile: false, hasTouch: false}], [2, {}]]) {
    const {page, context} = await session(browser, 320, options);
    try {
      await assertLegibleOverview(page, 320);
      const name = `${label}-320-cold-${attempt}.png`;
      await hook(page, "graph").screenshot({path: path.join(directory, name), style: captureStyle});
      report.screenshots.push(name);
    } finally { await context.close(); }
  }
  report.checks.push(`${label}: three cold 320px loads retain readable portrait positions and complete labels with touch and desktop browser contexts`);
}

async function dragPoint(page, start, end, touch = false) {
  const draggedId = await page.evaluate(({x, y}) => document.elementFromPoint(x, y)?.closest("[data-topology-node]")?.dataset.topologyNode, start);
  if (touch) {
    const channel = await page.context().newCDPSession(page);
    try {
      await channel.send("Input.dispatchTouchEvent", {type: "touchStart", touchPoints: [{x: start.x, y: start.y, id: 1}]});
      for (let step = 1; step <= 8; step++) {
        await channel.send("Input.dispatchTouchEvent", {type: "touchMove", touchPoints: [{id: 1,
          x: start.x + (end.x - start.x) * step / 8, y: start.y + (end.y - start.y) * step / 8}]});
      }
      if (draggedId) assert.equal(await page.locator(`[data-topology-node="${draggedId}"]`).evaluate(node => node.classList.contains("is-dragging")), true, "trusted touch drag raises its active card");
      await channel.send("Input.dispatchTouchEvent", {type: "touchEnd", touchPoints: []});
    } finally { await channel.detach(); }
  } else {
    await page.mouse.move(start.x, start.y);
    await page.mouse.down();
    await page.mouse.move(end.x, end.y, {steps: 8});
    await page.mouse.up();
  }
  await settleGraph(page);
  if (touch) await page.waitForTimeout(100);
  assert.equal(await hook(page, "graph").locator(".is-dragging").count(), 0, "completed mouse/touch gestures remove their temporary card layer");
}

async function setLayoutEditing(page, enabled) {
  const toggle = hook(page, "layout-edit");
  if ((await toggle.getAttribute("aria-pressed") === "true") !== enabled) await toggle.click();
  assert.equal(await toggle.getAttribute("aria-pressed"), String(enabled), "explicit layout toggle exposes its current state");
  assert.equal(await hook(page, "graph").getAttribute("data-layout-editing"), String(enabled), "canvas matches the explicit layout mode");
  await settleGraph(page);
}

async function touchScrollStart(page, onNode) {
  // Keep the real document, canvas and fixed mobile navigation in place. Pick a
  // visible starting point instead of dispatching a synthetic scroll event.
  await hook(page, "graph").evaluate(graph => window.scrollTo(0, graph.getBoundingClientRect().top + scrollY - 120));
  await page.waitForTimeout(100);
  const start = await hook(page, "graph").evaluate((graph, onNode) => {
    const bounds = graph.getBoundingClientRect();
    const top = Math.max(bounds.top + 24, 320), bottom = Math.min(bounds.bottom - 24, innerHeight - 180);
    if (onNode) {
      for (const node of graph.querySelectorAll("[data-topology-node]")) {
        const box = node.getBoundingClientRect(), x = box.left + box.width / 2, y = box.top + box.height / 2;
        if (y >= top && y <= bottom && x > bounds.left + 15 && x < bounds.right - 15
            && document.elementFromPoint(x, y)?.closest("[data-topology-node]") === node) return {x, y, id: node.dataset.topologyNode};
      }
    } else {
      for (let y = bottom; y >= top; y -= 24) for (let x = bounds.left + 20; x < bounds.right - 20; x += 24) {
        const item = document.elementFromPoint(x, y);
        if (item && graph.contains(item) && !item.closest("[data-topology-node]")) return {x, y};
      }
    }
    return null;
  }, onNode);
  assert.ok(start, `real mobile graph exposes a visible ${onNode ? "node" : "background"} swipe target`);
  return start;
}

async function nativeSwipe(page, start, dy = -190) {
  const channel = await page.context().newCDPSession(page);
  try {
    await channel.send("Input.dispatchTouchEvent", {type: "touchStart", touchPoints: [{id: 1, x: start.x, y: start.y}]});
    for (let step = 1; step <= 10; step++) {
      await channel.send("Input.dispatchTouchEvent", {type: "touchMove", touchPoints: [{id: 1, x: start.x, y: start.y + dy * step / 10}]});
      await page.waitForTimeout(20);
    }
    // Ending at rest avoids a long fling affecting the following assertion.
    await page.waitForTimeout(140);
    await channel.send("Input.dispatchTouchEvent", {type: "touchEnd", touchPoints: []});
  } finally { await channel.detach(); }
  await page.waitForTimeout(180);
  await settleGraph(page);
}

async function touchScrollNavigation(browser, label) {
  const state = await session(browser, 390);
  const {page, context, requests} = state;
  try {
    assert.equal(await hook(page, "layout-edit").getAttribute("aria-pressed"), "false", "mobile loads in reading mode, never in layout mode");
    const assertTouchPolicy = async editing => {
      const actions = await hook(page, "graph").evaluate(graph => ({
        graph: getComputedStyle(graph).touchAction,
        nodes: [...graph.querySelectorAll("[data-topology-node]")].map(node => getComputedStyle(node).touchAction),
      }));
      if (editing) assert.equal(actions.graph, "none", "layout mode alone claims native touch gestures for the canvas subtree");
      else for (const action of [actions.graph, ...actions.nodes]) {
        assert.ok(action === "auto" || action === "manipulation" || action.includes("pan-y"), "reading mode permits native vertical page scrolling on both canvas and cards");
      }
    };
    await assertTouchPolicy(false);
    const assertReadingSwipe = async onNode => {
      const start = await touchScrollStart(page, onNode);
      const before = await layoutState(page), selection = await hook(page, "select").inputValue();
      const beforeRequests = requests.length, initialScroll = await page.evaluate(() => scrollY);
      if (label === "chromium") {
        await nativeSwipe(page, start);
        assert.ok(await page.evaluate(() => scrollY) > initialScroll + 70, `trusted ${onNode ? "node" : "background"} swipe scrolls the real document`);
      } else {
        // WebKit exposes no CDP touch injection. Verify pointer cancellation and
        // the native-scroll CSS contract; do not pretend dispatchEvent scrolls.
        const result = await hook(page, "graph").evaluate((graph, start) => {
          const target = document.elementFromPoint(start.x, start.y);
          const states = [];
          for (const [type, y] of [["pointerdown", start.y], ["pointermove", start.y - 100], ["pointercancel", start.y - 100]]) {
            const event = new PointerEvent(type, {pointerType: "touch", pointerId: 912, isPrimary: true, clientX: start.x, clientY: y, bubbles: true, cancelable: true});
            target.dispatchEvent(event);
            states.push({prevented: event.defaultPrevented, dragging: graph.dataset.dragging === "true"});
          }
          return states;
        }, start);
        assert.ok(result.every(item => !item.prevented && !item.dragging), "reading touch never captures movement, suppresses native default or begins a canvas drag");
      }
      assert.deepEqual(await layoutState(page), before, "reading swipe never moves nodes, pans, zooms or rewrites inline ports");
      assert.equal(await hook(page, "select").inputValue(), selection, "scrolling from a card never selects it");
      assert.equal(requests.length, beforeRequests, "reading swipe never fetches selection data");
      assert.notEqual(await hook(page, "graph").getAttribute("data-dragging"), "true");
      assert.equal(await hook(page, "graph").locator(".is-dragging").count(), 0);
    };
    await assertReadingSwipe(false);
    await assertReadingSwipe(true);
    const targetId = await hook(page, "node").evaluateAll(nodes => nodes.find(node => node.getAttribute("aria-pressed") !== "true").dataset.topologyNode);
    await page.locator(`[data-topology-node="${targetId}"]`).tap();
    await selectionSettled(page, targetId);
    await settleGraph(page);
    assert.equal(await hook(page, "layout-edit").getAttribute("aria-pressed"), "false", "a normal node tap selects without enabling layout changes");
    await setLayoutEditing(page, true);
    await assertTouchPolicy(true);
    await hook(page, "graph").evaluate(graph => window.scrollTo(0, graph.getBoundingClientRect().top + scrollY + 100));
    await settleGraph(page);
    const exitVisible = await hook(page, "layout-edit").evaluate(button => {
      const bounds = button.getBoundingClientRect(), x = bounds.left + bounds.width / 2, y = bounds.top + bounds.height / 2;
      return bounds.top >= 0 && bounds.bottom < innerHeight - 90 && button.contains(document.elementFromPoint(x, y));
    });
    assert.equal(exitVisible, true, "the completion button stays visible and clickable when reading has scrolled into the middle of the canvas");
    const editingShot = `${label}-390-touch-layout-sticky.png`;
    await page.screenshot({path: path.join(directory, editingShot), style: captureStyle});
    report.screenshots.push(editingShot);
    const start = await touchScrollStart(page, true);
    const before = await layoutState(page);
    // Mouse remains available even on hybrid touch devices. Exit through the
    // real button click handler while its captured drag is still active.
    await page.mouse.move(start.x, start.y);
    await page.mouse.down();
    await page.mouse.move(start.x + 12, start.y + 10);
    assert.equal(await hook(page, "graph").locator(".is-dragging").count(), 1, "layout mode begins an active card drag");
    await hook(page, "layout-edit").evaluate(button => button.click());
    assert.notEqual(await hook(page, "graph").getAttribute("data-dragging"), "true", "leaving layout mode cancels an active gesture");
    assert.equal(await hook(page, "graph").locator(".is-dragging").count(), 0, "leaving layout mode removes the temporary active layer");
    const stopped = await layoutState(page);
    await page.mouse.move(start.x + 60, start.y + 50);
    await page.mouse.up();
    await settleGraph(page);
    assert.deepEqual(await layoutState(page), stopped, "a canceled gesture cannot continue moving after layout mode exits");
    assert.notDeepEqual(stopped.positions, before.positions, "exiting layout mode preserves changes already made rather than resetting the arrangement");
    await assertTouchPolicy(false);
    // Exercise the first native tap inside the 450 ms synthetic-click guard
    // left by the canceled drag, rather than waiting through another swipe.
    const immediateTap = await hook(page, "graph").evaluate(graph => {
      for (const node of graph.querySelectorAll('[data-topology-node][aria-pressed="false"]')) {
        const box = node.getBoundingClientRect(), x = box.left + box.width / 2, y = box.top + box.height / 2;
        if (y > 100 && y < innerHeight - 100 && document.elementFromPoint(x, y)?.closest("[data-topology-node]") === node) return {x, y, id: node.dataset.topologyNode};
      }
      return null;
    });
    assert.ok(immediateTap, "mobile graph exposes an unselected card for immediate tap recovery");
    // Reenter/finish without moving the page to start a deterministic guard.
    await hook(page, "layout-edit").evaluate(button => { button.click(); button.click(); });
    await page.touchscreen.tap(immediateTap.x, immediateTap.y);
    await selectionSettled(page, immediateTap.id);
    await settleGraph(page);
    assert.equal(await hook(page, "layout-edit").getAttribute("aria-pressed"), "false", "the first tap after completing a layout edit selects immediately without reentering layout mode");
    await assertReadingSwipe(false);
    await assertReadingSwipe(true);
    await screenshot(page, `${label}-390-touch-page-scroll`);
    await setLayoutEditing(page, true);
    await hook(page, "graph").focus();
    await page.keyboard.press("Escape");
    assert.equal(await hook(page, "layout-edit").getAttribute("aria-pressed"), "false", "Escape provides an accessible way back to page scrolling");
    await assertTouchPolicy(false);
    await setLayoutEditing(page, true);
    await hook(page, "layout-edit").focus();
    await page.keyboard.press("Escape");
    assert.equal(await hook(page, "layout-edit").getAttribute("aria-pressed"), "false", "Escape also exits immediately while focus remains on the layout button");
    await assertTouchPolicy(false);
    await assertReadOnly(state);
    await setLayoutEditing(page, true);
    await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pagehide", {persisted: true})));
    assert.equal(await hook(page, "layout-edit").getAttribute("aria-pressed"), "false", "leaving or restoring the page never leaves native scrolling captured");
    assert.equal(await hook(page, "graph").locator(".is-dragging").count(), 0);
    await page.reload();
    await hook(page, "root").waitFor();
    assert.equal(await hook(page, "layout-edit").getAttribute("aria-pressed"), "false", "layout manipulation is never sticky across page loads");
    await assertTouchPolicy(false);
    report.checks.push(`${label}: reading-mode ${label === "chromium" ? "trusted native page scrolling" : "touch-action/pointer lifecycle"} from background and cards, tap selection, explicit layout mode, active-gesture cancellation, and restored reading mode after exit/reload`);
  } finally { await page.mouse.up().catch(() => {}); await context.close(); }
}

async function directManipulation(browser, label, width, touch = false) {
  const state = await session(browser, width);
  const {page, context, requests} = state;
  try {
    const model = await (await context.request.get(topologyURL + "?format=json")).json();
    const source = model.links.find(link => link.source !== "hub").source;
    await selectAndWait(page, source);
    if (touch) await setLayoutEditing(page, true);
    await hook(page, "fit").click();
    await hook(page, "graph").scrollIntoViewIfNeeded();
    const original = await layoutState(page);
    const selected = await hook(page, "select").inputValue();
    const nodeId = model.links.find(link => link.source === selected && link.target !== "hub")?.target || "hub";
    const node = page.locator(`[data-topology-node="${nodeId}"]`);
    const box = await node.boundingBox();
    const beforeRequests = requests.length;
    const initialScroll = await page.evaluate(() => scrollY);
    const start = {x: box.x + box.width / 2, y: box.y + box.height / 2};
    await dragPoint(page, start, {x: start.x + 37, y: start.y + 29}, touch);
    const moved = await layoutState(page);
    assert.notDeepEqual(moved.positions.find(node => node.id === nodeId), original.positions.find(node => node.id === nodeId), "drag changes node world coordinates");
    assert.notDeepEqual(moved.spokes, original.spokes, "dragging any leaf updates its structural VPS spoke");
    if (nodeId === "hub" || nodeId === selected) assert.notDeepEqual(moved.edges, original.edges, "dragging a permission-arrow endpoint updates that arrow");
    else assert.deepEqual(moved.edges, original.edges, "dragging a leaf target with no crossing path leaves the selected VPS arrow unchanged");
    assert.deepEqual(moved.ports, original.ports, "drag preserves inline protocol/port contents inside the moving cards");
    assert.equal(await hook(page, "select").inputValue(), selected, "dragging does not select the dragged node");
    assert.equal(requests.length, beforeRequests, "dragging does not trigger a selection fetch");
    if (touch) assert.equal(await page.evaluate(() => scrollY), initialScroll, "touch node drag does not scroll the document");
    await Promise.all([page.waitForResponse(jsonResponse), hook(page, "refresh").click()]);
    await page.waitForFunction(() => !document.querySelector("[data-topology-root]").hasAttribute("aria-busy"));
    assert.deepEqual((await layoutState(page)).positions, moved.positions, "refresh preserves custom node placement");
    await selectAndWait(page, nodeId);
    assert.deepEqual((await layoutState(page)).positions, moved.positions, "selection preserves custom node placement");
    await hook(page, "graph").scrollIntoViewIfNeeded();
    const background = await hook(page, "graph").evaluate(graph => {
      const box = graph.getBoundingClientRect();
      for (let y = 20; y < box.height - 70; y += 40) for (let x = 20; x < box.width - 70; x += 40) {
        const element = document.elementFromPoint(box.left + x, box.top + y);
        if (element && graph.contains(element) && !element.closest("[data-topology-node]")) return {x: box.left + x, y: box.top + y};
      }
      return null;
    });
    assert.ok(background, "graph exposes a drag target on the background");
    const beforePan = await layoutState(page);
    const beforePanScroll = await page.evaluate(() => scrollY);
    await dragPoint(page, background, {x: background.x + 42, y: background.y + 31}, touch);
    const panned = await layoutState(page);
    assert.notDeepEqual(panned.viewport, beforePan.viewport, "background drag pans the viewport");
    assert.deepEqual(panned.positions, beforePan.positions, "panning does not change world coordinates");
    if (touch) assert.equal(await page.evaluate(() => scrollY), beforePanScroll, "touch panning stays inside the graph");
    const beforeZoom = panned.viewport.scale;
    await openViewTools(page);
    await hook(page, "zoom-in").click();
    await settleGraph(page);
    assert.ok((await layoutState(page)).viewport.scale > beforeZoom, "zoom-in raises scale");
    await hook(page, "zoom-out").click();
    await settleGraph(page);
    assert.ok((await layoutState(page)).viewport.scale < beforeZoom * 1.01, "zoom-out lowers scale");
    await closeViewTools(page);
    await hook(page, "graph").scrollIntoViewIfNeeded();
    const zoomBox = await hook(page, "graph").boundingBox();
    const gestureScale = (await layoutState(page)).viewport.scale;
    const gestureScroll = await page.evaluate(() => scrollY);
    if (touch) {
      const channel = await page.context().newCDPSession(page);
      const center = {x: zoomBox.x + zoomBox.width / 2, y: zoomBox.y + zoomBox.height / 2};
      try {
        await channel.send("Input.dispatchTouchEvent", {type: "touchStart", touchPoints: [{id: 1, x: center.x - 28, y: center.y}, {id: 2, x: center.x + 28, y: center.y}]});
        for (let step = 1; step <= 6; step++) {
          const gap = 28 + step * 5;
          await channel.send("Input.dispatchTouchEvent", {type: "touchMove", touchPoints: [{id: 1, x: center.x - gap, y: center.y}, {id: 2, x: center.x + gap, y: center.y}]});
        }
        await channel.send("Input.dispatchTouchEvent", {type: "touchEnd", touchPoints: []});
      } finally { await channel.detach(); }
    } else {
      await page.mouse.move(zoomBox.x + zoomBox.width / 2, zoomBox.y + zoomBox.height / 2);
      await page.mouse.wheel(0, -180);
    }
    await settleGraph(page);
    assert.ok((await layoutState(page)).viewport.scale > gestureScale, `${touch ? "pinch" : "wheel"} zoom changes scale`);
    assert.equal(await page.evaluate(() => scrollY), gestureScroll, "zoom gesture does not scroll the document");
    await hook(page, "fit").click();
    assert.deepEqual((await layoutState(page)).positions, moved.positions, "fit preserves customized layout");
    await direction(page, "reverse");
    await assertGraph(page);
    await assertCardEdges(page);
    await direction(page, "forward");
    await assertGraph(page);
    await assertCardEdges(page);
    assert.deepEqual((await layoutState(page)).positions, moved.positions, "content height changes in either direction preserve dragged world coordinates");
    await screenshot(page, `${label}-${width}-${touch ? "touch" : "mouse"}-dragged`);
    if (!touch) {
      await hook(page, "graph").focus();
      const keyboardView = (await layoutState(page)).viewport;
      await page.keyboard.press("ArrowRight");
      await settleGraph(page);
      assert.notDeepEqual((await layoutState(page)).viewport, keyboardView, "canvas can be panned from the keyboard");
      await node.focus();
      const keyboardPositions = (await layoutState(page)).positions;
      const beforeKeyboardRequests = requests.length;
      await page.keyboard.press("Alt+ArrowRight");
      await settleGraph(page);
      assert.notDeepEqual((await layoutState(page)).positions, keyboardPositions, "keyboard moves a focused node");
      assert.equal(requests.length, beforeKeyboardRequests);
    }
    await openViewTools(page);
    await hook(page, "reset").click();
    assert.deepEqual((await layoutState(page)).positions, original.positions, "reset restores the deterministic layout");
    if (!touch) {
      await closeViewTools(page);
      await selectAndWait(page, source);
      await hook(page, "graph").focus();
      await page.keyboard.press("ArrowRight");
      await settleGraph(page);
      const beforeResize = await layoutState(page);
      const beforeWidth = await hook(page, "node").first().evaluate(node => node.getBoundingClientRect().width);
      await page.setViewportSize({width: 590, height: 844});
      await settleGraph(page);
      const resized = await layoutState(page);
      const afterWidth = await hook(page, "node").first().evaluate(node => node.getBoundingClientRect().width);
      assert.ok(afterWidth < beforeWidth, "crossing the mobile breakpoint changes card width");
      assert.deepEqual(resized.positions, beforeResize.positions, "responsive card sizing never rearranges a user-adjusted layout");
      assert.equal(resized.viewport.scale, beforeResize.viewport.scale, "responsive sizing preserves the user's zoom");
      assert.notDeepEqual(resized.edges, beforeResize.edges, "responsive card widths redraw edge endpoints even at unchanged zoom");
      await assertGraph(page);
      await assertCardEdges(page);
      await page.setViewportSize({width, height: 1000});
      await settleGraph(page);
      const restored = await layoutState(page);
      assert.deepEqual(restored.positions, beforeResize.positions);
      assert.deepEqual(restored.edges, beforeResize.edges, "restoring the breakpoint restores the exact endpoint geometry");
    }
    await closeViewTools(page);
    await selectAndWait(page, "hub");
    await direction(page, "reverse");
    await hook(page, "fit").click();
    await hook(page, "graph").scrollIntoViewIfNeeded();
    const hub = page.locator('[data-topology-node="hub"]'), hubBox = await hub.boundingBox();
    const beforeHubDrag = await layoutState(page), beforeHubRequests = requests.length;
    assert.ok(beforeHubDrag.edges.length > 0, "hub reverse view has real retained arrows to exercise");
    await dragPoint(page, {x: hubBox.x + hubBox.width / 2, y: hubBox.y + hubBox.height / 2},
      {x: hubBox.x + hubBox.width / 2 + 21, y: hubBox.y + hubBox.height / 2 + 17}, touch);
    const afterHubDrag = await layoutState(page);
    assert.deepEqual(afterHubDrag.edges.map(edge => edge.key), beforeHubDrag.edges.map(edge => edge.key), "hub drag preserves every retained permission");
    assert.ok(afterHubDrag.edges.every((edge, index) => edge.path !== beforeHubDrag.edges[index].path), "moving the hub updates every retained permission arrow");
    assert.ok(afterHubDrag.spokes.every((spoke, index) => JSON.stringify(spoke) !== JSON.stringify(beforeHubDrag.spokes[index])), "moving the hub updates every structural spoke");
    assert.deepEqual(afterHubDrag.ports, beforeHubDrag.ports, "hub drag preserves all source port scopes");
    assert.equal(requests.length, beforeHubRequests, "hub drag remains local and read-only");
    await assertGraph(page);
    await assertReadOnly(state);
    report.checks.push(`${label} ${width}: ${touch ? "trusted touch and pinch" : "mouse, wheel, and keyboard"} node drag/pan, inline-port persistence, zoom/fit/reset, layout persistence, and directional inspection`);
  } finally { await context.close(); }
}

async function layerPriority(browser, label) {
  const state = await session(browser, 1440);
  const {page, context, requests} = state;
  try {
    const model = await (await context.request.get(topologyURL + "?format=json")).json();
    const selected = model.nodes.find(node => model.links.some(link => link.source === node.id)
      && model.nodes.some(other => other.id !== node.id && !model.links.some(link => link.source === node.id && link.target === other.id)));
    assert.ok(selected, "layer fixture includes a selected source, authorized peer, and ordinary node");
    await selectAndWait(page, selected.id);
    const peerId = model.links.find(link => link.source === selected.id).target;
    const ordinary = model.nodes.find(node => node.id !== selected.id && !model.links.some(link => link.source === selected.id && link.target === node.id));
    const card = id => page.locator(`[data-topology-node="${id}"]`);
    await hook(page, "fit").click();
    await hook(page, "graph").scrollIntoViewIfNeeded();
    const selectedBox = await card(selected.id).boundingBox(), peerBox = await card(peerId).boundingBox();
    const center = box => ({x: box.x + box.width / 2, y: box.y + box.height / 2});
    const peerCenter = center(peerBox), beforeRequests = requests.length;
    const hit = point => page.evaluate(({x, y}) => document.elementFromPoint(x, y)?.closest("[data-topology-node]")?.dataset.topologyNode, point);
    await dragPoint(page, center(selectedBox), peerCenter);
    await page.evaluate(() => document.activeElement?.blur());
    assert.equal(await hit(peerCenter), peerId, "authorized peer paints above an overlapping selected card when neither has keyboard focus");
    const ordinaryBox = await card(ordinary.id).boundingBox();
    const ordinaryCenter = center(ordinaryBox);
    await page.mouse.move(ordinaryCenter.x, ordinaryCenter.y);
    await page.mouse.down();
    await page.mouse.move(peerCenter.x, peerCenter.y, {steps: 8});
    await settleGraph(page);
    assert.equal(await card(ordinary.id).evaluate(node => node.classList.contains("is-dragging")), true, "the actively dragged card exposes its temporary top layer");
    assert.equal(await hit(peerCenter), ordinary.id, "dragged ordinary card paints above peer and selected cards");
    await page.mouse.up();
    await settleGraph(page);
    await page.evaluate(() => document.activeElement?.blur());
    assert.equal(await hook(page, "graph").locator(".is-dragging").count(), 0, "drag completion clears the temporary node layer");
    assert.equal(await hit(peerCenter), peerId, "peer resumes its top layer after drag completion");
    await page.keyboard.press("Tab");
    await card(ordinary.id).focus();
    assert.equal(await card(ordinary.id).evaluate(node => node.matches(":focus-visible")), true);
    assert.equal(await hit(peerCenter), ordinary.id, "keyboard-focused node is visible above an overlapping peer");
    await page.evaluate(() => document.activeElement?.blur());
    assert.equal(await hit(peerCenter), peerId);
    assert.equal(requests.length, beforeRequests, "layer and drag interaction never fetch or change selection");
    const positions = (await layoutState(page)).positions;
    await direction(page, "reverse");
    await mode(page, "overview");
    assert.equal(await hook(page, "graph").locator(".is-peer, .is-dragging").count(), 0, "overview clears peer and drag layers");
    assert.deepEqual((await layoutState(page)).positions, positions, "layer/content cleanup never resets the deliberately dragged positions");
    await assertReadOnly(state);
    report.checks.push(`${label}: actual overlapping hit-tests prove peer above ordinary/selected, active drag above peer, keyboard focus visible, and layer cleanup without RPC or position reset`);
  } finally { await context.close(); }
}

async function interruptedGestures(browser, label) {
  const state = await session(browser, 1440);
  const {page, context} = state;
  let releaseResponse;
  try {
    const original = await (await context.request.get(topologyURL + "?format=json")).json();
    const target = original.nodes.find(node => node.kind === "awg" && node.id !== original.selected_id);
    const targetNode = page.locator(`[data-topology-node="${target.id}"]`);
    await hook(page, "graph").scrollIntoViewIfNeeded();
    await hook(page, "graph").evaluate(graph => {
      graph.addEventListener("pointerdown", event => { graph.dataset.qaPointerId = String(event.pointerId); }, {capture: true});
    });
    let box = await targetNode.boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down();
    await page.mouse.move(box.x + box.width / 2 + 14, box.y + box.height / 2 + 11);
    await hook(page, "graph").evaluate(graph => graph.releasePointerCapture(Number(graph.dataset.qaPointerId)));
    const graphBox = await hook(page, "graph").boundingBox();
    await page.mouse.move(graphBox.x - 5, graphBox.y + 40);
    await page.mouse.up();
    await settleGraph(page);
    assert.notEqual(await hook(page, "graph").getAttribute("data-dragging"), "true", "lost pointer capture cancels the gesture without sticky dragging");
    assert.equal(await hook(page, "graph").locator(".is-dragging").count(), 0, "lost capture removes the temporary node top layer");
    box = await targetNode.boundingBox();
    const beforeNew = await layoutState(page);
    await dragPoint(page, {x: box.x + box.width / 2, y: box.y + box.height / 2}, {x: box.x + box.width / 2 + 20, y: box.y + box.height / 2 + 12});
    assert.notDeepEqual((await layoutState(page)).positions, beforeNew.positions, "a new gesture works after losing capture");

    const changed = structuredClone(original);
    changed.nodes = changed.nodes.filter(node => node.id !== target.id);
    changed.relations = changed.relations.filter(relation => relation.node.id !== target.id);
    changed.links = changed.links.filter(link => link.source !== target.id && link.target !== target.id);
    changed.summary.nodes -= 1; changed.summary.awg -= 1; changed.summary.enabled -= 1;
    let reached;
    const pending = new Promise(resolve => { releaseResponse = resolve; });
    const intercepted = new Promise(resolve => { reached = resolve; });
    await page.route(jsonRoute, async route => {
      reached(); await pending;
      try { await route.fulfill({status: 200, contentType: "application/json", body: JSON.stringify(changed)}); }
      catch (error) { if (!/closed|disposed|aborted|interception|already handled/i.test(error.message)) throw error; }
    });
    await hook(page, "refresh").click();
    await intercepted;
    await hook(page, "graph").scrollIntoViewIfNeeded();
    box = await targetNode.boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down();
    await page.mouse.move(box.x + box.width / 2 + 12, box.y + box.height / 2 + 10);
    releaseResponse();
    await targetNode.waitFor({state: "detached"});
    const afterRemoval = await layoutState(page);
    await page.mouse.move(box.x + box.width / 2 + 43, box.y + box.height / 2 + 32);
    await page.mouse.up();
    await settleGraph(page);
    assert.deepEqual((await layoutState(page)).viewport, afterRemoval.viewport, "removing a dragged node cannot reinterpret its coordinates as a background pan");
    assert.notEqual(await hook(page, "graph").getAttribute("data-dragging"), "true");
    await assertGraph(page, changed.links);
    await assertReadOnly(state);
    report.checks.push(`${label}: lost pointer capture and refresh removal of a dragged node cancel cleanly without stale gestures or camera jumps`);
  } finally { releaseResponse?.(); await page.mouse.up().catch(() => {}); await context.close(); }
}

async function responsiveThemes(browser, label, width) {
  const state = await session(browser, width);
  const {page, context} = state;
  try {
    assert.equal(await page.locator('button[data-topology-mode="overview"]').getAttribute("aria-pressed"), "true", "initial graph is a clean star overview");
    assert.equal(await hook(page, "view-options").evaluate(details => details.open), false, "secondary view controls are initially collapsed");
    assert.equal(await hook(page, "full-details").evaluate(details => details.open), false, "the exhaustive permission list is initially collapsed with JavaScript");
    await assertGraph(page);
    await assertLegibleOverview(page, width);
    if (width === 390) {
      const name = `${label}-390-initial-graph.png`;
      await hook(page, "graph").screenshot({path: path.join(directory, name), style: captureStyle});
      report.screenshots.push(name);
    }
    assert.match(await hook(page, "root").innerText(), /权限视图不是连通性测试/, "live handshakes must not imply proven reachability");
    const clients = await hook(page, "node").evaluateAll(items => items.map(node => node.getAttribute("data-topology-node")).filter(id => id !== "hub"));
    assert.ok(clients.length > 1, "rich fixture graph has clients");
    const target = clients.find(id => id.startsWith("vless:")) || clients[1];
    const targetButton = hook(page, "node").filter({hasText: target.split(":").slice(1).join(":")});
    await (width < 768 ? targetButton.tap() : targetButton.click());
    await selectionSettled(page, target);
    assert.match(await hook(page, "details").textContent(), new RegExp(target.split(":").slice(1).join(":")));
    assert.equal(await page.locator('button[data-topology-mode="relations"]').getAttribute("aria-pressed"), "true", "node click enters relationship mode");
    for (const theme of ["dark", "light", "sky"]) {
      await setTheme(page, width, theme);
      await assertControlContrast(page, label, width, theme);
      await assertGraph(page);
      await assertLegibleOverview(page, width);
      await screenshot(page, `${label}-${width}-${theme}`);
      if (width === 1440) {
        const name = `${label}-${width}-${theme}-controls.png`;
        await page.locator(".topology-panel").screenshot({path: path.join(directory, name), style: captureStyle});
        report.screenshots.push(name);
      }
      if (theme === "light") {
        const name = `${label}-${width}-graph.png`;
        await hook(page, "graph").screenshot({path: path.join(directory, name), style: captureStyle});
        report.screenshots.push(name);
      }
    }
    await assertReadOnly(state);
    report.checks.push(`${label} ${width}: clean overview, all nodes, single-direction inspection, touch/click selection, three themes, no overflow or navigation`);
  } finally { await context.close(); }
}

async function keyboardAndErrors(browser, label) {
  const state = await session(browser, 1440);
  const {page, context} = state;
  try {
    const original = await (await context.request.get(topologyURL + "?format=json")).json();
    const target = original.nodes.find(node => node.kind === "awg" && node.id !== original.selected_id);
    const button = hook(page, "node").filter({hasText: target.name});
    await button.focus();
    await page.keyboard.press("Enter");
    await selectionSettled(page, target.id);
    assert.equal(await hook(page, "select").inputValue(), target.id);
    await hook(page, "refresh").focus();
    await Promise.all([page.waitForResponse(jsonResponse), page.keyboard.press("Space")]);
    const select = hook(page, "select");
    await select.focus();
    // Native type-ahead works in macOS headless browsers; their OS arrow-key
    // popup is not controlled by Playwright. "v" uniquely selects VPS here.
    await page.keyboard.press("v");
    await page.keyboard.press("Enter");
    await selectionSettled(page, "hub");
    assert.equal(await select.inputValue(), "hub", "native selection works from the keyboard");
    const before = await viewState(page);
    await page.route(jsonRoute, route => route.fulfill({status: 503, contentType: "application/json", body: JSON.stringify({code: "snapshot_unavailable", error: "暂时无法读取节点连接关系，请稍后重试。"})}));
    await Promise.all([page.waitForResponse(jsonResponse), hook(page, "refresh").click()]);
    await page.waitForFunction(() => /失败|无法|重试/.test(document.querySelector("[data-topology-status]").textContent));
    assert.deepEqual(await viewState(page), before, "refresh error preserves selection, nodes, options, and details");
    const cachedIds = new Set([original.selected_id, target.id, "hub"]);
    const uncachedTarget = original.nodes.find(node => !cachedIds.has(node.id));
    assert.ok(uncachedTarget, "failed selection must exercise an actual uncached request");
    await Promise.all([page.waitForResponse(jsonResponse), choose(page, uncachedTarget.id)]);
    await page.waitForFunction(() => !document.querySelector("[data-topology-refresh]").disabled);
    assert.deepEqual(await viewState(page), before, "failed selection restores the previous selection and complete view");
    await assertGraph(page);
    await screenshot(page, `${label}-refresh-error`);
    await page.unroute(jsonRoute);
    await page.route(jsonRoute, route => route.fulfill({status: 200, contentType: "text/html", body: "<!doctype html><title>Login</title><form>synthetic expired session</form>"}));
    await Promise.all([page.waitForResponse(jsonResponse), hook(page, "refresh").click()]);
    await page.waitForFunction(() => !document.querySelector("[data-topology-refresh]").disabled);
    assert.deepEqual(await viewState(page), before, "expired login HTML cannot replace the last good view");
    assert.doesNotMatch(await hook(page, "root").innerHTML(), /synthetic expired session/);
    const missingKind = structuredClone(original);
    delete missingKind.nodes.find(node => node.kind === "awg").kind;
    const unknownLink = structuredClone(original);
    assert.ok(unknownLink.links.length, "rich fixture has confirmed permissions");
    unknownLink.links[0].status = "unknown";
    const missingLinks = structuredClone(original);
    delete missingLinks.links;
    for (const body of ["{bad json", JSON.stringify({nodes: [], selected_id: "hub"}), JSON.stringify(missingKind), JSON.stringify(unknownLink), JSON.stringify(missingLinks)]) {
      await page.unroute(jsonRoute);
      await page.route(jsonRoute, route => route.fulfill({status: 200, contentType: "application/json", body}));
      await Promise.all([page.waitForResponse(jsonResponse), hook(page, "refresh").click()]);
      await page.waitForFunction(() => !document.querySelector("[data-topology-refresh]").disabled);
      assert.deepEqual(await viewState(page), before, "malformed JSON/model cannot replace the last good view");
      assert.equal(await hook(page, "status").getAttribute("data-state"), "error");
    }
    await assertReadOnly(state);
    report.checks.push(`${label}: keyboard node/select/refresh; HTTP errors, expired login, malformed JSON/model preserve the last good view`);
  } finally { await context.close(); }
}

async function cancellationAndTimeout(browser, label) {
  const state = await session(browser);
  const {page, context} = state;
  const releases = [];
  function gate() {
    let release;
    const promise = new Promise(resolve => { release = resolve; });
    releases.push(release);
    return {promise, release};
  }
  try {
    const original = await (await context.request.get(topologyURL + "?format=json")).json();
    const target = original.nodes.find(node => node.kind === "awg" && node.id !== original.selected_id);
    const next = await (await context.request.get(topologyURL + "?format=json&node=" + encodeURIComponent(target.id))).json();
    const before = await viewState(page);
    const modeReached = gate(), modeDelayed = gate();
    await page.route(jsonRoute, async route => {
      modeReached.release(); await modeDelayed.promise;
      try { await route.fulfill({status: 200, contentType: "application/json", body: JSON.stringify(next)}); }
      catch (error) { if (!/closed|disposed|aborted|interception|already handled/i.test(error.message)) throw error; }
    });
    await choose(page, target.id);
    await modeReached.promise;
    await mode(page, "overview");
    assert.equal(await hook(page, "root").getAttribute("aria-busy"), null, "returning to overview cancels a pending selection");
    assert.deepEqual(await viewState(page), before, "returning to overview restores the prior selection and layout");
    modeDelayed.release();
    await page.waitForTimeout(150);
    assert.deepEqual(await viewState(page), before, "a late selected-node response cannot force the user out of overview");
    await page.unroute(jsonRoute);
    const reached = gate(), delayed = gate();
    await page.route(jsonRoute, async route => {
      reached.release();
      await delayed.promise;
      try { await route.fulfill({status: 200, contentType: "application/json", body: JSON.stringify(next)}); }
      catch (error) { if (!/closed|disposed|aborted|interception|already handled/i.test(error.message)) throw error; }
    });
    await choose(page, target.id);
    await reached.promise;
    assert.equal(await hook(page, "root").getAttribute("aria-busy"), "true");
    await page.evaluate(() => {
      window.dispatchEvent(new PageTransitionEvent("pagehide", {persisted: true}));
      window.dispatchEvent(new PageTransitionEvent("pageshow", {persisted: true}));
    });
    assert.equal(await hook(page, "refresh").isEnabled(), true);
    assert.equal(await hook(page, "root").getAttribute("aria-busy"), null);
    assert.deepEqual(await viewState(page), before, "pagehide cancels selection and resets the prior view");
    delayed.release();
    await page.waitForTimeout(150);
    assert.deepEqual(await viewState(page), before, "response arriving after pagehide cannot replace the view");
    await page.unroute(jsonRoute);
    const timeoutReached = gate(), timeoutHeld = gate();
    await page.route(jsonRoute, async route => {
      timeoutReached.release();
      await timeoutHeld.promise;
      try { await route.fulfill({status: 200, contentType: "application/json", body: JSON.stringify(original)}); }
      catch (error) { if (!/closed|disposed|aborted|interception|already handled/i.test(error.message)) throw error; }
    });
    await page.evaluate(() => {
      const originalTimer = window.setTimeout.bind(window);
      // Accelerate only the production 15-second fetch deadline, not UI timers.
      let accelerated = false;
      window.setTimeout = (callback, delay, ...args) => {
        if (delay === 15000 && !accelerated) { accelerated = true; return originalTimer(callback, 100, ...args); }
        return originalTimer(callback, delay, ...args);
      };
    });
    await hook(page, "refresh").click();
    await timeoutReached.promise;
    await page.waitForFunction(() => /超时/.test(document.querySelector("[data-topology-status]").textContent));
    assert.deepEqual(await viewState(page), before, "deadline preserves all displayed data");
    assert.equal(await hook(page, "refresh").isEnabled(), true, "timeout restores the refresh control");
    assert.equal(await hook(page, "root").getAttribute("aria-busy"), null);
    await screenshot(page, `${label}-390-timeout`);
    timeoutHeld.release();
    await page.unroute(jsonRoute);
    await Promise.all([page.waitForResponse(jsonResponse), hook(page, "refresh").click()]);
    await page.waitForFunction(() => document.querySelector("[data-topology-status]").dataset.state === "ready");
    await assertReadOnly(state);
    report.checks.push(`${label}: overview return and pagehide cancel late responses; 15-second deadline preserves the view and permits retry`);
  } finally { releases.forEach(release => release()); await context.close(); }
}

async function stressAndRace(browser, label) {
  const state = await session(browser);
  const {page, context} = state;
  let releaseOld;
  try {
    const original = await (await context.request.get(topologyURL + "?format=json")).json();
    let reachedOld;
    const oldReached = new Promise(resolve => { reachedOld = resolve; });
    const oldPending = new Promise(resolve => { releaseOld = resolve; });
    let delayId = null;
    await page.route(jsonRoute, async route => {
      const id = new URL(route.request().url()).searchParams.get("node") || "hub";
      if (id === delayId) { reachedOld(); await oldPending; }
      try { await route.fulfill({status: 200, contentType: "application/json", body: JSON.stringify(syntheticModel(original, id))}); }
      catch (error) { if (!/closed|disposed|aborted|interception|already handled/i.test(error.message)) throw error; }
    });
    const renderStarted = Date.now();
    await Promise.all([page.waitForResponse(jsonResponse), hook(page, "refresh").click()]);
    await page.waitForFunction(() => document.querySelector("[data-topology-select]").options.length === 41);
    await settleGraph(page);
    const denseModel = syntheticModel(original);
    await assertGraph(page, denseModel.links);
    const renderMs = Date.now() - renderStarted;
    assert.ok(renderMs < 8000, "40-node dense graph renders without freezing the page");
    assert.equal(await hook(page, "node").count(), 41, "all 40 clients and the hub are mounted together");
    const positions = (await layoutState(page)).positions;
    await openViewTools(page);
    await hook(page, "search").fill("synthetic-39");
    assert.equal(await hook(page, "node").count(), 41, "search preserves every node");
    assert.equal(await hook(page, "graph").locator("[data-topology-node].is-match").count(), 1, "search highlights its match");
    assert.deepEqual((await layoutState(page)).positions, positions, "search changes the camera without rearranging nodes");
    await assertGraph(page, denseModel.links);
    await screenshot(page, `${label}-390-search-40-nodes`);
    await hook(page, "search").fill("no-synthetic-node-matches");
    assert.equal(await hook(page, "node").count(), 41, "an unmatched search does not hide configured nodes");
    assert.equal(await hook(page, "graph").locator("[data-topology-node].is-match").count(), 0);
    await hook(page, "search").fill("");
    await closeViewTools(page);
    const frameMs = await page.evaluate(async () => {
      const started = performance.now();
      for (let frame = 0; frame < 12; frame++) await new Promise(resolve => requestAnimationFrame(resolve));
      return performance.now() - started;
    });
    assert.ok(frameMs < 2000, "dense graph continues to process animation frames");
    report.performance.push({browser: label, nodes: 41, directedLinks: denseModel.links.length, renderMs, twelveFramesMs: Math.round(frameMs)});
    const delayedId = "awg:synthetic-00", finalId = "awg:synthetic-01";
    delayId = delayedId;
    await choose(page, delayedId);
    await oldReached;
    await Promise.all([page.waitForResponse(response => jsonResponse(response) && new URL(response.url()).searchParams.get("node") === finalId), choose(page, finalId)]);
    await page.waitForFunction(id => document.querySelector("[data-topology-select]").value === id, finalId);
    const finalDetails = await hook(page, "details").textContent();
    assert.match(finalDetails, /synthetic-01/);
    releaseOld();
    // Let both the network and rendering queues settle after the stale response.
    await page.waitForTimeout(200);
    assert.equal(await hook(page, "select").inputValue(), finalId, "late response cannot restore stale selection");
    assert.equal(await hook(page, "details").textContent(), finalDetails, "late response cannot replace current details");
    await hook(page, "fit").click();
    await assertGraph(page, denseModel.links);
    assert.equal(await hook(page, "node").count(), 41, "directional inspection never drops nodes");
    await screenshot(page, `${label}-390-many-nodes-focused`);
    await mode(page, "overview");
    await screenshot(page, `${label}-390-many-nodes`);
    await page.setViewportSize({width: 320, height: 844});
    await page.waitForTimeout(50);
    await hook(page, "fit").click();
    await assertGraph(page, denseModel.links);
    await mode(page, "relations");
    await screenshot(page, `${label}-320-many-nodes`);
    await page.setViewportSize({width: 768, height: 1000});
    await page.waitForTimeout(50);
    await hook(page, "fit").click();
    await assertGraph(page, denseModel.links);
    await screenshot(page, `${label}-768-many-nodes`);
    await page.setViewportSize({width: 1440, height: 1000});
    await page.waitForTimeout(50);
    await hook(page, "fit").click();
    await assertGraph(page, denseModel.links);
    await hook(page, "graph").scrollIntoViewIfNeeded();
    const dragNode = page.locator('[data-topology-node="awg:synthetic-02"]');
    const dragBox = await dragNode.boundingBox();
    const beforeDenseDrag = await layoutState(page);
    const requestCount = state.requests.length;
    const dragStarted = Date.now();
    await dragPoint(page, {x: dragBox.x + dragBox.width / 2, y: dragBox.y + dragBox.height / 2},
      {x: dragBox.x + dragBox.width / 2 + 29, y: dragBox.y + dragBox.height / 2 + 19});
    const denseDragMs = Date.now() - dragStarted;
    const afterDenseDrag = await layoutState(page);
    assert.notDeepEqual(afterDenseDrag.positions, beforeDenseDrag.positions, "dense graph remains draggable");
    assert.notDeepEqual(afterDenseDrag.spokes, beforeDenseDrag.spokes, "dense graph updates the dragged leaf's VPS spoke");
    assert.deepEqual(afterDenseDrag.edges, beforeDenseDrag.edges, "an unrelated leaf drag does not invent or change permission arrows");
    assert.equal(state.requests.length, requestCount, "dense node drag does not fetch selection data");
    assert.ok(denseDragMs < 3500, "dense graph handles an eight-step drag without freezing");
    report.performance.find(item => item.browser === label).denseDragMs = denseDragMs;
    await screenshot(page, `${label}-1440-many-nodes`);
    await assertReadOnly(state);
    report.checks.push(`${label}: all 40 clients plus hub, 1600-direction payload with selected-direction rendering, search without hiding, dense graph performance, and stale request protection`);
  } finally { releaseOld?.(); await context.close(); }
}

async function fixturesAndFallback(browser, label) {
  const state = await session(browser);
  const {context, page} = state;
  try {
    for (const scenario of ["empty", "pending", "error"]) {
      assert.equal((await context.request.get(new URL(`__preview__/scenario/${scenario}/`, base).href)).status(), 200);
      const response = await page.goto(topologyURL);
      assert.equal(response.status(), scenario === "error" ? 503 : 200);
      await hook(page, "root").waitFor();
      if (scenario === "empty") {
        assert.equal(await hook(page, "node").count(), 1);
        assert.match(await hook(page, "root").innerText(), /暂无|还没有|尚无|尚未|没有/);
      }
      if (scenario === "pending") assert.match(await hook(page, "root").innerText(), /待.*应用|待同步|尚未同步|未同步/);
      if (scenario === "error") assert.match(await hook(page, "root").innerText(), /无法|失败|重试/);
      await screenshot(page, `${label}-390-${scenario}`);
    }
  } finally { await context.close(); }
  const fallback = await session(browser, 390, {javaScriptEnabled: false});
  try {
    assert.match(await fallback.page.locator("body").innerText(), /JavaScript|脚本|未启用交互图/);
    assert.match(await hook(fallback.page, "details").innerText(), /VPS/);
    assert.equal(await hook(fallback.page, "full-details").evaluate(details => details.open), true, "full fallback detail stays open without JavaScript");
    assert.ok(await hook(fallback.page, "select").isVisible(), "native selection is visible without JavaScript");
    await screenshot(fallback.page, `${label}-390-noscript`);
    report.checks.push(`${label}: empty/pending/error fixtures and readable no-JavaScript fallback`);
  } finally { await fallback.context.close(); }
}

(async () => {
  try {
    for (const [label, engine] of [["chromium", chromium], ["webkit", webkit]]) {
      const browser = await engine.launch();
      try {
        if (process.argv.includes("--touch-scroll-only")) {
          await touchScrollNavigation(browser, label);
          if (label === "chromium") await directManipulation(browser, label, 390, true);
          await directManipulation(browser, label, 1440);
          continue;
        }
        if (process.argv.includes("--layer-smoke")) {
          await layerSmoke(browser, label);
          await directManipulation(browser, label, 1440);
          await layerPriority(browser, label);
          continue;
        }
        if (process.argv.includes("--readability-audit")) {
          await readabilityAudit(browser, label);
          continue;
        }
        const anonymous = await browser.newContext();
        try {
          const response = await anonymous.request.get(topologyURL + "?format=json", {maxRedirects: 0});
          assert.ok([302, 401, 403].includes(response.status()), "topology requires authentication");
        } finally { await anonymous.close(); }
        if (process.argv.includes("--interruptions-only")) {
          await interruptedGestures(browser, label);
          continue;
        }
        if (!process.argv.includes("--keyboard-only") && !process.argv.includes("--functional-only")) {
          await coldMobileLayouts(browser, label);
          for (const width of [320, 390, 768, 1440]) await responsiveThemes(browser, label, width);
          await readabilityAudit(browser, label);
        }
        if (process.argv.includes("--visual-only")) continue;
        await layerSmoke(browser, label);
        await layerPriority(browser, label);
        if (!process.argv.includes("--theme-gesture-only")) await keyboardAndErrors(browser, label);
        if (process.argv.includes("--keyboard-only")) continue;
        await directManipulation(browser, label, 1440);
        await touchScrollNavigation(browser, label);
        if (label === "chromium") await directManipulation(browser, label, 390, true);
        await interruptedGestures(browser, label);
        if (process.argv.includes("--theme-gesture-only")) continue;
        await stressAndRace(browser, label);
        await cancellationAndTimeout(browser, label);
        await fixturesAndFallback(browser, label);
      } finally { await browser.close(); }
    }
    assert.deepEqual(report.errors, [], "no browser runtime errors");
    assert.deepEqual(report.blocked, [], "no external requests");
    console.log(JSON.stringify({directory, checks: report.checks, screenshots: report.screenshots.length, readabilityScenes: report.readability.length,
      performance: report.performance, errors: report.errors, blocked: report.blocked}, null, 2));
  } catch (error) {
    report.failure = error.stack;
    console.error(error.stack);
    process.exitCode = 1;
  } finally {
    fs.writeFileSync(path.join(directory, "report.json"), JSON.stringify(report, null, 2));
    console.log(`Topology QA artifacts: ${directory}`);
  }
})();
