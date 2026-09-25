"use strict";

// Isolated browser regression with synthetic fixtures only; never targets a VPS.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {chromium, webkit} = require("playwright");
const base = new URL(process.argv[2] || "http://127.0.0.1:8765/");
if (base.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(base.hostname)
    || base.username || base.password || base.pathname !== "/") throw new Error("Only an isolated loopback preview is allowed.");
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "server-kit-topology-"));
console.log(`Topology QA started: ${directory}`);
const report = {directory, checks: [], screenshots: [], errors: [], blocked: [], performance: [], controlStyles: []};
const password = "Preview-only-2026!";
const topologyURL = new URL("network/topology/", base).href;
const hook = (page, name) => page.locator(`[data-topology-${name}]`);
const jsonRoute = url => url.origin === base.origin && url.pathname === "/network/topology/" && url.searchParams.get("format") === "json";
const jsonResponse = response => jsonRoute(new URL(response.url()));

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
  const navigations = [], requests = [];
  page.on("request", request => {
    requests.push({url: request.url(), method: request.method()});
    if (request.isNavigationRequest() && request.frame() === page.mainFrame()) navigations.push(request.url());
  });
  await page.goto(topologyURL);
  await hook(page, "root").waitFor();
  navigations.length = 0;
  return {context, page, navigations, requests};
}

async function screenshot(page, label) {
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true, `${label}: page overflow`);
  await page.screenshot({path: path.join(directory, `${label}.png`), fullPage: true});
  report.screenshots.push(`${label}.png`);
}

async function choose(page, id) {
  // Native selection is available at every zoom and pan position.
  await hook(page, "select").selectOption(id);
}

async function assertGraph(page, expectedLinks = null) {
  // Read geometry and metadata atomically while pointer movement can redraw.
  const value = await hook(page, "graph").evaluate(graph => {
    const nodeElements = [...graph.querySelectorAll("[data-topology-node]")];
    const edgeElements = [...graph.querySelectorAll("[data-topology-edge]")].filter(edge => getComputedStyle(edge.closest("[data-topology-link]") || edge).display !== "none");
    const nodes = nodeElements.map(node => ({id: node.dataset.topologyNode, tag: node.tagName, pressed: node.getAttribute("aria-pressed"),
      x: Number(node.dataset.worldX), y: Number(node.dataset.worldY)}));
    const selectedId = document.querySelector("[data-topology-select]").value;
    const edges = edgeElements.map(edge => ({tag: edge.tagName.toLowerCase(), source: edge.dataset.source, target: edge.dataset.target,
      key: edge.dataset.linkKey, dash: getComputedStyle(edge).strokeDasharray, marker: edge.getAttribute("marker-end"),
      reverseMarker: edge.getAttribute("marker-start"), bidirectional: edge.dataset.bidirectional === "true"}));
    const labels = [...graph.querySelectorAll("[data-topology-edge-label]")].filter(label => getComputedStyle(label.closest("[data-topology-link]") || label).display !== "none").map(label => ({source: label.dataset.source, target: label.dataset.target,
      key: label.dataset.linkKey, text: label.textContent.trim()}));
    const spokes = [...graph.querySelectorAll("[data-topology-spoke]")].map(line => ({source: line.dataset.source, target: line.dataset.target}));
    return {nodes, selectedId, edges, labels, spokes, options: document.querySelector("[data-topology-select]").options.length,
      initialLinks: JSON.parse(document.getElementById("topology-data").textContent).links,
      focus: document.querySelector("[data-topology-focus]").checked};
  });
  const {nodes, selectedId, edges, labels, spokes} = value;
  assert.equal(nodes.filter(node => node.id === "hub").length, 1, "one central VPS");
  assert.ok(nodes.every(node => node.tag === "BUTTON"), "graph nodes are keyboard-operable buttons");
  assert.equal(nodes.length, value.options, "every configured node exists in the graph at once");
  assert.ok(nodes.every(node => Number.isFinite(node.x) && Number.isFinite(node.y)), "nodes expose finite layout coordinates");
  assert.equal(nodes.filter(node => node.pressed === "true").length, 1, "one selected node remains present at every zoom");
  assert.equal(spokes.length, nodes.length - 1, "one structural hub spoke for every client");
  const ids = new Set(nodes.map(node => node.id));
  for (const line of spokes) {
    assert.ok((line.source === "hub") !== (line.target === "hub"), "structural spokes remain distinct from client-to-client permission links");
    assert.ok(ids.has(line.source) && ids.has(line.target));
  }
  const expected = (expectedLinks || value.initialLinks).filter(link => !value.focus || link.source === selectedId || link.target === selectedId);
  const directions = edges.flatMap(edge => edge.bidirectional ? [[edge.source, edge.target].join("→"), [edge.target, edge.source].join("→")] : [[edge.source, edge.target].join("→")]);
  assert.deepEqual(directions.sort(), expected.map(edge => [edge.source, edge.target].join("→")).sort(),
    "only confirmed allowed/partial directed links are drawn; unknown/inactive directions are absent");
  assert.equal(labels.length, edges.length, "each permission path has a port label");
  for (const edge of edges) {
    assert.equal(edge.tag, "path");
    assert.ok(edge.dash && edge.dash !== "none" && edge.dash !== "0px", "permission links are dashed");
    assert.ok(edge.marker, "every permission path has a directional arrow");
    if (edge.bidirectional) assert.ok(edge.reverseMarker, "combined mutual permissions have arrows in both directions");
    const label = labels.find(label => label.key === edge.key);
    assert.ok(label && label.text, "each permission path has its own readable label");
    const link = expected.find(link => link.source === edge.source && link.target === edge.target);
    assert.ok(link.scopes.every(scope => label.text.includes(scope)), "edge labels include exact configured protocol/port scopes");
    if (edge.bidirectional) {
      const reverse = expected.find(link => link.source === edge.target && link.target === edge.source);
      assert.deepEqual(reverse.scopes, link.scopes, "only matching port scopes may share a bidirectional path");
    }
  }
  assert.equal(await page.locator("[data-topology-prev], [data-topology-next], [data-topology-page]").count(), 0, "graph has no pagination");
}

async function assertReadOnly(session) {
  assert.deepEqual(session.navigations, [], "graph interaction must not navigate");
  assert.ok(session.requests.every(request => request.method === "GET"), "topology only sends read-only GET requests");
  const contents = await hook(session.page, "root").innerHTML();
  assert.doesNotMatch(contents, /synthetic-preview-exit-secret|Preview-only-2026|BEGIN (?:RSA |OPENSSH )?PRIVATE KEY|vless:\/\//);
  const storage = await session.page.evaluate(() => JSON.stringify({local: {...localStorage}, session: {...sessionStorage}}));
  assert.doesNotMatch(storage, /synthetic-preview-exit-secret|Preview-only-2026/);
}

async function viewState(page) {
  return {
    selected: await hook(page, "select").inputValue(),
    options: await hook(page, "select").locator("option").allTextContents(),
    nodes: await hook(page, "node").allTextContents(),
    details: await hook(page, "details").innerText(),
    graph: await layoutState(page),
  };
}

async function layoutState(page) {
  return hook(page, "graph").evaluate(graph => ({
    positions: [...graph.querySelectorAll("[data-topology-node]")].map(node => ({id: node.dataset.topologyNode,
      x: Number(node.dataset.worldX), y: Number(node.dataset.worldY)})),
    viewport: {x: Number(graph.dataset.viewportX), y: Number(graph.dataset.viewportY), scale: Number(graph.dataset.viewportScale)},
    edges: [...graph.querySelectorAll("[data-topology-edge]")].map(edge => ({key: edge.dataset.linkKey, path: edge.getAttribute("d")})),
    labels: [...graph.querySelectorAll("[data-topology-edge-label]")].map(label => ({key: label.dataset.linkKey,
      x: label.getAttribute("x"), y: label.getAttribute("y"), transform: label.getAttribute("transform")})),
  }));
}

async function settleGraph(page) {
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
}

async function assertLegibleOverview(page, width) {
  await settleGraph(page);
  const result = await hook(page, "graph").evaluate(graph => {
    const box = graph.getBoundingClientRect();
    const names = [...graph.querySelectorAll("[data-topology-node] strong")].map(node => ({name: node.textContent, box: node.getBoundingClientRect()}));
    const labels = [...graph.querySelectorAll("[data-topology-edge-label]")].map(node => ({name: node.dataset.linkKey, box: node.getBoundingClientRect()}));
    const nodes = [...graph.querySelectorAll("[data-topology-node]")].map(node => node.getBoundingClientRect());
    const overlap = (a, b) => a.left < b.right - .5 && a.right > b.left + .5 && a.top < b.bottom - .5 && a.bottom > b.top + .5;
    return {
      clippedLabels: labels.filter(({box: item}) => item.left < box.left - 1 || item.right > box.right + 1 || item.top < box.top - 1 || item.bottom > box.bottom + 1).map(item => item.name),
      overlappingNames: names.flatMap((a, index) => names.slice(index + 1).filter(b => overlap(a.box, b.box)).map(b => [a.name, b.name])),
      verticalFraction: (Math.max(...nodes.map(node => node.y + node.height / 2)) - Math.min(...nodes.map(node => node.y + node.height / 2))) / box.height,
    };
  });
  assert.deepEqual(result.clippedLabels, [], "default overview keeps complete protocol/port labels inside the canvas");
  assert.deepEqual(result.overlappingNames, [], "default overview does not obscure node names with neighboring labels");
  if (width <= 390) assert.ok(result.verticalFraction > .5, "cold mobile layout uses the available portrait canvas instead of shrinking a desktop layout");
}

async function assertControlContrast(page, label, width, theme) {
  const styles = await page.evaluate(async () => {
    const buttons = [...document.querySelectorAll(".topology-content button.secondary-button")].filter(button => button.getClientRects().length);
    await Promise.all(buttons.flatMap(button => button.getAnimations()).map(animation => animation.finished.catch(() => {})));
    const luminance = color => {
      const rgb = color.match(/[\d.]+/g).slice(0, 3).map(Number).map(value => {
        const channel = value / 255;
        return channel <= .04045 ? channel / 12.92 : ((channel + .055) / 1.055) ** 2.4;
      });
      return rgb[0] * .2126 + rgb[1] * .7152 + rgb[2] * .0722;
    };
    return buttons.map(button => {
      const style = getComputedStyle(button);
      const backgroundLum = luminance(style.backgroundColor), foregroundLum = luminance(style.color);
      return {text: button.textContent.trim(), disabled: button.disabled, background: style.backgroundColor, color: style.color,
        appearance: style.appearance, webkitAppearance: style.webkitAppearance, image: style.backgroundImage,
        backgroundLum, contrast: (Math.max(backgroundLum, foregroundLum) + .05) / (Math.min(backgroundLum, foregroundLum) + .05)};
    });
  });
  assert.ok(styles.length >= 5, "topology controls expose themed buttons");
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
      await hook(page, "graph").screenshot({path: path.join(directory, name)});
      report.screenshots.push(name);
    } finally { await context.close(); }
  }
  report.checks.push(`${label}: three cold 320px loads retain readable portrait positions and complete labels with touch and desktop browser contexts`);
}

async function dragPoint(page, start, end, touch = false) {
  if (touch) {
    const channel = await page.context().newCDPSession(page);
    try {
      await channel.send("Input.dispatchTouchEvent", {type: "touchStart", touchPoints: [{x: start.x, y: start.y, id: 1}]});
      for (let step = 1; step <= 8; step++) {
        await channel.send("Input.dispatchTouchEvent", {type: "touchMove", touchPoints: [{id: 1,
          x: start.x + (end.x - start.x) * step / 8, y: start.y + (end.y - start.y) * step / 8}]});
      }
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
}

async function directManipulation(browser, label, width, touch = false) {
  const state = await session(browser, width);
  const {page, context, requests} = state;
  try {
    await hook(page, "fit").click();
    await hook(page, "graph").scrollIntoViewIfNeeded();
    const original = await layoutState(page);
    const selected = await hook(page, "select").inputValue();
    const nodeId = original.positions.find(node => node.id !== "hub" && node.id !== selected).id;
    const node = page.locator(`[data-topology-node="${nodeId}"]`);
    const box = await node.boundingBox();
    const beforeRequests = requests.length;
    const initialScroll = await page.evaluate(() => scrollY);
    const start = {x: box.x + box.width / 2, y: box.y + box.height / 2};
    await dragPoint(page, start, {x: start.x + 37, y: start.y + 29}, touch);
    const moved = await layoutState(page);
    assert.notDeepEqual(moved.positions.find(node => node.id === nodeId), original.positions.find(node => node.id === nodeId), "drag changes node world coordinates");
    assert.notDeepEqual(moved.edges, original.edges, "drag updates permission path geometry");
    assert.notDeepEqual(moved.labels, original.labels, "drag updates port label positions");
    assert.equal(await hook(page, "select").inputValue(), selected, "dragging does not select the dragged node");
    assert.equal(requests.length, beforeRequests, "dragging does not trigger a selection fetch");
    if (touch) assert.equal(await page.evaluate(() => scrollY), initialScroll, "touch node drag does not scroll the document");
    await Promise.all([page.waitForResponse(jsonResponse), hook(page, "refresh").click()]);
    await page.waitForFunction(() => !document.querySelector("[data-topology-root]").hasAttribute("aria-busy"));
    assert.deepEqual((await layoutState(page)).positions, moved.positions, "refresh preserves custom node placement");
    await Promise.all([page.waitForResponse(jsonResponse), choose(page, nodeId)]);
    await page.waitForFunction(() => !document.querySelector("[data-topology-root]").hasAttribute("aria-busy"));
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
    await hook(page, "zoom-in").click();
    await settleGraph(page);
    assert.ok((await layoutState(page)).viewport.scale > beforeZoom, "zoom-in raises scale");
    await hook(page, "zoom-out").click();
    await settleGraph(page);
    assert.ok((await layoutState(page)).viewport.scale < beforeZoom * 1.01, "zoom-out lowers scale");
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
    await hook(page, "focus").check();
    await assertGraph(page);
    await hook(page, "focus").uncheck();
    await assertGraph(page);
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
    await hook(page, "reset").click();
    assert.deepEqual((await layoutState(page)).positions, original.positions, "reset restores the deterministic layout");
    await assertReadOnly(state);
    report.checks.push(`${label} ${width}: ${touch ? "trusted touch and pinch" : "mouse, wheel, and keyboard"} node drag/pan, port-label updates, zoom/fit/reset, layout persistence, and optional edge focus`);
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
    assert.equal(await hook(page, "focus").isChecked(), false, "the initial graph displays all permission links");
    await assertGraph(page);
    await assertLegibleOverview(page, width);
    if (width === 390) {
      const name = `${label}-390-initial-graph.png`;
      await hook(page, "graph").screenshot({path: path.join(directory, name)});
      report.screenshots.push(name);
    }
    assert.match(await hook(page, "root").innerText(), /未检测/);
    const clients = await hook(page, "node").evaluateAll(items => items.map(node => node.getAttribute("data-topology-node")).filter(id => id !== "hub"));
    assert.ok(clients.length > 1, "rich fixture graph has clients");
    const target = clients.find(id => id.startsWith("vless:")) || clients[1];
    const targetButton = hook(page, "node").filter({hasText: target.split(":").slice(1).join(":")});
    await Promise.all([page.waitForResponse(jsonResponse), width < 768 ? targetButton.tap() : targetButton.click()]);
    await page.waitForFunction(id => document.querySelector("[data-topology-select]").value === id, target);
    assert.match(await hook(page, "details").innerText(), new RegExp(target.split(":").slice(1).join(":")));
    for (const theme of ["dark", "light", "sky"]) {
      if (width <= 900) await page.locator("[data-mobile-menu] > summary").click();
      await page.locator(`[data-theme-value="${theme}"]:visible`).first().click();
      if (width <= 900) await page.locator("[data-mobile-menu-close]").click();
      assert.equal(await page.locator("html").getAttribute("data-theme"), theme);
      await assertControlContrast(page, label, width, theme);
      await assertGraph(page);
      await assertLegibleOverview(page, width);
      await screenshot(page, `${label}-${width}-${theme}`);
      if (width === 1440) {
        const name = `${label}-${width}-${theme}-controls.png`;
        await page.locator(".topology-panel").screenshot({path: path.join(directory, name)});
        report.screenshots.push(name);
      }
      if (theme === "light") {
        const name = `${label}-${width}-graph.png`;
        await hook(page, "graph").screenshot({path: path.join(directory, name)});
        report.screenshots.push(name);
      }
    }
    await assertReadOnly(state);
    report.checks.push(`${label} ${width}: every node, dashed permission directions/port labels, touch/click selection, three themes, no overflow or navigation`);
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
    await Promise.all([page.waitForResponse(jsonResponse), page.keyboard.press("Enter")]);
    assert.equal(await hook(page, "select").inputValue(), target.id);
    await hook(page, "refresh").focus();
    await Promise.all([page.waitForResponse(jsonResponse), page.keyboard.press("Space")]);
    const select = hook(page, "select");
    await select.focus();
    await Promise.all([page.waitForResponse(jsonResponse), (async () => {
      // Native type-ahead works in macOS headless browsers; their OS arrow-key
      // popup is not controlled by Playwright. "v" uniquely selects VPS here.
      await page.keyboard.press("v");
      await page.keyboard.press("Enter");
    })()]);
    assert.equal(await select.inputValue(), "hub", "native selection works from the keyboard");
    const before = await viewState(page);
    await page.route(jsonRoute, route => route.fulfill({status: 503, contentType: "application/json", body: JSON.stringify({code: "snapshot_unavailable", error: "暂时无法读取节点连接关系，请稍后重试。"})}));
    await Promise.all([page.waitForResponse(jsonResponse), hook(page, "refresh").click()]);
    await page.waitForFunction(() => /失败|无法|重试/.test(document.querySelector("[data-topology-status]").textContent));
    assert.deepEqual(await viewState(page), before, "refresh error preserves selection, nodes, options, and details");
    await Promise.all([page.waitForResponse(jsonResponse), choose(page, target.id)]);
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
    report.checks.push(`${label}: pagehide cancels late responses and restores controls; 15-second deadline preserves the view and permits retry`);
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
    const finalDetails = await hook(page, "details").innerText();
    assert.match(finalDetails, /synthetic-01/);
    releaseOld();
    // Let both the network and rendering queues settle after the stale response.
    await page.waitForTimeout(200);
    assert.equal(await hook(page, "select").inputValue(), finalId, "late response cannot restore stale selection");
    assert.equal(await hook(page, "details").innerText(), finalDetails, "late response cannot replace current details");
    await hook(page, "fit").click();
    await hook(page, "focus").check();
    await assertGraph(page, denseModel.links);
    assert.equal(await hook(page, "node").count(), 41, "focus only filters edges");
    await screenshot(page, `${label}-390-many-nodes-focused`);
    await hook(page, "focus").uncheck();
    await screenshot(page, `${label}-390-many-nodes`);
    await page.setViewportSize({width: 320, height: 844});
    await page.waitForTimeout(50);
    await hook(page, "fit").click();
    await assertGraph(page, denseModel.links);
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
    assert.notDeepEqual(afterDenseDrag.edges, beforeDenseDrag.edges, "dense graph updates its paths while dragging");
    assert.equal(state.requests.length, requestCount, "dense node drag does not fetch selection data");
    assert.ok(denseDragMs < 3500, "dense graph handles an eight-step drag without freezing");
    report.performance.find(item => item.browser === label).denseDragMs = denseDragMs;
    await screenshot(page, `${label}-1440-many-nodes`);
    await assertReadOnly(state);
    report.checks.push(`${label}: all 40 clients plus hub, 1600 directed permissions, search without hiding, focus without dropping nodes, dense graph performance, and stale request protection`);
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
        const anonymous = await browser.newContext();
        try {
          const response = await anonymous.request.get(topologyURL + "?format=json", {maxRedirects: 0});
          assert.ok([302, 401, 403].includes(response.status()), "topology requires authentication");
        } finally { await anonymous.close(); }
        if (process.argv.includes("--interruptions-only")) {
          await interruptedGestures(browser, label);
          continue;
        }
        if (!process.argv.includes("--keyboard-only")) {
          await coldMobileLayouts(browser, label);
          for (const width of [320, 390, 768, 1440]) await responsiveThemes(browser, label, width);
        }
        if (process.argv.includes("--visual-only")) continue;
        if (!process.argv.includes("--theme-gesture-only")) await keyboardAndErrors(browser, label);
        if (process.argv.includes("--keyboard-only")) continue;
        await directManipulation(browser, label, 1440);
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
    console.log(JSON.stringify(report, null, 2));
  } catch (error) {
    report.failure = error.stack;
    console.error(error.stack);
    process.exitCode = 1;
  } finally {
    fs.writeFileSync(path.join(directory, "report.json"), JSON.stringify(report, null, 2));
    console.log(`Topology QA artifacts: ${directory}`);
  }
})();
