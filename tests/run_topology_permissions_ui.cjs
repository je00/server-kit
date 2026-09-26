"use strict";

// Local-only regression using models projected by the real Python backend.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {spawnSync} = require("node:child_process");
const {chromium, webkit} = require("playwright");
const {assertCardEdges, assertInlinePorts, geometryFindings} = require("./topology_inline_assertions.cjs");
const base = new URL(process.argv[2] || "http://127.0.0.1:8808/");
assert.ok(base.protocol === "http:" && ["localhost", "127.0.0.1"].includes(base.hostname)
  && !base.username && !base.password && base.pathname === "/", "only an isolated loopback preview is allowed");
const fixtureFile = path.join(__dirname, "test_topology_permissions_fixture.py");
const projected = spawnSync(process.env.TOPOLOGY_TEST_PYTHON || "python3", [fixtureFile, "--json"], {encoding: "utf8", maxBuffer: 4 * 1024 * 1024});
assert.equal(projected.status, 0, projected.stderr || "Python projection failed");
const packet = JSON.parse(projected.stdout);
assert.equal(packet.generated_by, "dashboard.topology.build_topology");
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "server-kit-topology-permissions-"));
const report = {directory, projector: packet.generated_by, checks: [], screenshots: [], peerStyles: [], layoutFindings: [], requests: [], errors: [], external: []};
const topologyURL = new URL("network/topology/", base).href;
const hook = (page, name) => page.locator(`[data-topology-${name}]`);
const isJSON = url => url.origin === base.origin && url.pathname === "/network/topology/" && url.searchParams.get("format") === "json";
const captureStyle = ".skip-link:not(:focus) { visibility: hidden !important; }";
console.log(`Topology permissions QA: ${directory}`);

async function settle(page) {
  await page.waitForFunction(() => !document.querySelector("[data-topology-root]").hasAttribute("aria-busy"));
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
}

async function select(page, id) {
  if (await hook(page, "select").inputValue() === id) {
    await page.locator('button[data-topology-mode="relations"]').click();
  } else {
    await hook(page, "select").selectOption(id);
  }
  await page.waitForFunction(id => !document.querySelector("[data-topology-root]").hasAttribute("aria-busy")
    && document.querySelector("[data-topology-select]").value === id
    && document.querySelector('[data-topology-node][aria-pressed="true"]')?.dataset.topologyNode === id
    && document.querySelector('button[data-topology-mode="relations"]').getAttribute("aria-pressed") === "true"
    && document.querySelector("[data-topology-status]").dataset.state !== "error", id);
  await settle(page);
}

async function setTheme(page, width, theme) {
  if (width <= 900) await page.locator("[data-mobile-menu] > summary").click();
  await page.locator(`[data-theme-value="${theme}"]:visible`).first().click();
  if (width <= 900) await page.locator("[data-mobile-menu-close]").click();
  assert.equal(await page.locator("html").getAttribute("data-theme"), theme);
  await settle(page);
}

async function assertPeers(page, model, direction, overview = false) {
  const expected = overview ? [] : model.links.filter(link => direction === "forward" ? link.source === model.selected_id : link.target === model.selected_id)
    .map(link => direction === "forward" ? link.target : link.source).sort();
  const nodes = await hook(page, "node").evaluateAll(items => items.map(node => ({id: node.dataset.topologyNode,
    peer: node.dataset.topologyPeer || null, classPeer: node.classList.contains("is-peer"), selected: node.getAttribute("aria-pressed") === "true"})));
  assert.deepEqual(nodes.filter(node => node.classPeer).map(node => node.id).sort(), expected, "peer frames preserve every authorized counterpart, including leaf-to-leaf permissions without paths");
  assert.deepEqual(nodes.filter(node => node.peer).map(node => node.id).sort(), expected, "peer metadata is removed from every unrelated, inactive, unknown, and selected node");
  assert.ok(nodes.filter(node => node.classPeer).every(node => !node.selected && node.peer === (direction === "forward" ? "outbound" : "inbound")),
    "a selected node is never its own peer, and the frame records the correct access direction");
}

async function peerStyles(page, engine, width, theme, caseName) {
  const styles = await hook(page, "node").evaluateAll(async nodes => {
    await Promise.race([Promise.all(nodes.flatMap(node => node.getAnimations()).map(animation => animation.finished.catch(() => {}))), new Promise(resolve => setTimeout(resolve, 500))]);
    const rgba = value => {
      const values = value.match(/[\d.]+/g).map(Number);
      // color-mix(in srgb, ...) serializes normalized color(srgb ...) channels
      // in Chromium, while WebKit may serialize the same fill as rgb(...).
      const channels = values.slice(0, 3).map(channel => /^color\(srgb /.test(value) ? channel * 255 : channel);
      return [...channels, values[3] ?? 1];
    };
    const blend = (front, back) => front.slice(0, 3).map((value, index) => value * front[3] + back[index] * (1 - front[3]));
    const background = node => {
      const layers = [];
      for (let current = node; current; current = current.parentElement) layers.unshift(rgba(getComputedStyle(current).backgroundColor));
      return layers.reduce((color, layer) => blend(layer, color), [255, 255, 255]);
    };
    const luminance = rgb => {
      const values = rgb.map(value => { const channel = value / 255; return channel <= .04045 ? channel / 12.92 : ((channel + .055) / 1.055) ** 2.4; });
      return values[0] * .2126 + values[1] * .7152 + values[2] * .0722;
    };
    const contrast = (a, b) => { const first = luminance(a), second = luminance(b); return (Math.max(first, second) + .05) / (Math.min(first, second) + .05); };
    return nodes.filter(node => node.classList.contains("is-peer") || node.getAttribute("aria-pressed") === "true").map(node => {
      const style = getComputedStyle(node), bg = background(node), name = node.querySelector("strong"), state = node.querySelector(".topology-node-state");
      const marker = node.querySelector(".topology-node-selected:not([hidden])"), markerBackground = marker ? background(marker) : null;
      const color = rgba(style.borderTopColor);
      return {id: node.dataset.topologyNode, kind: node.classList.contains("kind-awg") ? "awg" : node.classList.contains("kind-vless") ? "vless" : "hub",
        selected: node.getAttribute("aria-pressed") === "true", stateColor: getComputedStyle(state).color,
        border: style.borderTopColor, background: style.backgroundColor, effectiveBackground: bg, color: blend(color, bg), width: parseFloat(style.borderTopWidth), height: node.getBoundingClientRect().height,
        portContrasts: [...node.querySelectorAll(".topology-node-port")].map(port => contrast(blend(rgba(getComputedStyle(port).color), bg), bg)),
        rateContrasts: [...node.querySelectorAll(".topology-node-rates")].map(rate => contrast(blend(rgba(getComputedStyle(rate).color), bg), bg)),
        currentContrast: marker ? contrast(blend(rgba(getComputedStyle(marker).color), markerBackground), markerBackground) : null,
        nameContrast: contrast(blend(rgba(getComputedStyle(name).color), bg), bg), stateContrast: contrast(blend(rgba(getComputedStyle(state).color), bg), bg)};
    });
  });
  for (const item of styles) {
    assert.ok(item.width >= 2, `${engine}/${width}/${theme}/${item.id}: peer frame is at least 2 CSS px`);
    assert.ok(item.nameContrast >= 4.5, `${engine}/${width}/${theme}/${item.id}: name text contrast ${item.nameContrast.toFixed(2)} is readable`);
    assert.ok(item.stateContrast >= 4.5, `${engine}/${width}/${theme}/${item.id}: kind/state text contrast ${item.stateContrast.toFixed(2)} is readable`);
    assert.ok(item.portContrasts.every(value => value >= 4.5), "inline protocol/port text meets normal-text contrast");
    assert.ok(item.rateContrasts.every(value => value >= 4.5), "the new rate row meets normal-text contrast without masking permission scopes");
    if (item.currentContrast !== null) assert.ok(item.currentContrast >= 4.5, "current-node marker meets normal-text contrast");
    if (item.selected) assert.equal(item.border, item.stateColor, "selected card uses its own type color, not an unrelated warm frame");
    const [red, green, blue] = item.color;
    if (item.kind === "awg") assert.ok(blue > red + 15 && green > red, "AWG peers use a recognizable blue frame");
    if (item.kind === "vless") assert.ok(blue > green + 15 && red > green + 10, "VLESS peers use a recognizable purple frame");
    if (item.kind === "hub") assert.ok(red > blue + 25 && red > green + 10, "VPS peers use a recognizable warm frame");
  }
  const byKind = Object.values(Object.fromEntries(styles.map(item => [item.kind, item])));
  for (let first = 0; first < byKind.length; first++) for (let second = first + 1; second < byKind.length; second++) {
    const distance = Math.hypot(...byKind[first].color.map((value, channel) => value - byKind[second].color[channel]));
    assert.ok(distance >= 45, "different node kinds have visibly distinct peer-frame colors");
  }
  report.peerStyles.push({engine, width, theme, case: caseName, nodes: styles});
}

async function overview(page, model, requests) {
  const before = await hook(page, "node").evaluateAll(items => items.map(node => ({id: node.dataset.topologyNode, x: node.dataset.worldX, y: node.dataset.worldY})));
  const beforeRequests = requests.length;
  await page.locator('button[data-topology-mode="overview"]').click();
  await settle(page);
  assert.equal(await hook(page, "edge").count(), 0);
  await assertPeers(page, model, "forward", true);
  await assertInlinePorts(page, model.links, model.selected_id, "forward", true);
  await assertCardEdges(page);
  assert.equal(requests.length, beforeRequests, "returning to overview removes peer frames without a fetch");
  assert.deepEqual(await hook(page, "node").evaluateAll(items => items.map(node => ({id: node.dataset.topologyNode, x: node.dataset.worldX, y: node.dataset.worldY}))), before,
    "peer cleanup never rearranges nodes");
}

async function assertDirection(page, model, direction, expectedCount) {
  const positions = await hook(page, "node").evaluateAll(nodes => nodes.map(node => ({id: node.dataset.topologyNode, x: node.dataset.worldX, y: node.dataset.worldY})));
  await page.locator(`button[data-topology-direction="${direction}"]`).click();
  await settle(page);
  assert.deepEqual(await hook(page, "node").evaluateAll(nodes => nodes.map(node => ({id: node.dataset.topologyNode, x: node.dataset.worldX, y: node.dataset.worldY}))), positions,
    "direction-dependent content height changes never reset node positions");
  const expected = model.links.filter(link => direction === "forward" ? link.source === model.selected_id : link.target === model.selected_id);
  assert.equal(expected.length, expectedCount, "the real backend produced the expected number of confirmed directions");
  assert.equal(await hook(page, "node").count(), 12, "all twelve nodes remain on one canvas");
  const spokes = await hook(page, "spoke").evaluateAll(items => items.map(spoke => ({source: spoke.dataset.source, target: spoke.dataset.target, dash: getComputedStyle(spoke).strokeDasharray})));
  assert.equal(spokes.length, model.nodes.length - 1, "every leaf retains its structural VPS spoke");
  assert.deepEqual(spokes.map(spoke => spoke.source).sort(), model.nodes.filter(node => node.id !== "hub").map(node => node.id).sort());
  assert.ok(spokes.every(spoke => spoke.target === "hub" && spoke.dash !== "none"), "star spokes stay dashed and never connect two leaves");
  const paths = await hook(page, "edge").evaluateAll(edges => edges.map(edge => ({source: edge.dataset.source, target: edge.dataset.target,
    dash: getComputedStyle(edge).strokeDasharray, marker: edge.getAttribute("marker-end"), bidirectional: edge.dataset.bidirectional})));
  const drawn = expected.filter(link => link.source === "hub" || link.target === "hub");
  assert.deepEqual(paths.map(link => `${link.source}→${link.target}`).sort(), drawn.map(link => `${link.source}→${link.target}`).sort(),
    "only VPS-involving permissions have arrows; leaf-to-leaf paths are absent rather than merely hidden");
  assert.ok(paths.every(edge => edge.marker && edge.bidirectional !== "true" && edge.dash !== "none"), "confirmed permissions are dashed, directed, and never reversed");
  assert.match(await hook(page, "canvas-summary").innerText(), new RegExp(`当前方向 ${expectedCount} 条授权`), "authorization count includes the leaf-to-leaf permissions without arrows");
  const rows = await hook(page, "inspector").locator("[data-topology-access-target]").evaluateAll(items => items.map(item => ({id: item.dataset.topologyAccessTarget,
    scopes: [...item.querySelectorAll(".topology-access-scopes li")].map(scope => scope.textContent)})));
  assert.deepEqual(rows.sort((a, b) => a.id.localeCompare(b.id)), expected.map(link => ({id: direction === "forward" ? link.target : link.source, scopes: link.scopes})).sort((a, b) => a.id.localeCompare(b.id)),
    "the visible inspector contains every exact backend scope and no additional access");
  await assertPeers(page, model, direction);
  const inline = await assertInlinePorts(page, model.links, model.selected_id, direction);
  const layoutFindings = geometryFindings(inline);
  assert.deepEqual(layoutFindings, [], "inline port rows are inside non-overlapping cards, including dense hub inbound");
  await assertCardEdges(page);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
  return layoutFindings;
}

async function capture(page, name) {
  await page.evaluate(() => document.activeElement?.blur());
  await page.locator(".topology-panel").screenshot({path: path.join(directory, name), style: captureStyle});
  report.screenshots.push(name);
}

async function scenario(browser, engine, width) {
  const context = await browser.newContext({viewport: {width, height: width < 768 ? 844 : 1000}, ...(width < 768 ? {isMobile: true, hasTouch: true} : {})});
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  const requests = [], allRequests = [], navigations = [];
  let missingContext = false;
  try {
    await context.route("**/*", route => {
      const url = new URL(route.request().url());
      if (url.origin === base.origin) return route.continue();
      report.external.push(url.href);
      return route.abort();
    });
    page.on("pageerror", error => report.errors.push(error.message));
    await page.goto(new URL("login/", base).href);
    await page.locator('[name="username"]').fill("preview");
    await page.locator('[name="password"]').fill("Preview-only-2026!");
    await Promise.all([page.waitForURL(base.href), page.locator('button[type="submit"]').click()]);
    await page.route(isJSON, route => {
      const id = new URL(route.request().url()).searchParams.get("node");
      const model = missingContext ? packet.missing_context : packet.models[id] || packet.models[packet.initial_selected];
      return route.fulfill({status: 200, contentType: "application/json", body: JSON.stringify(model)});
    });
    await page.route(url => url.origin === base.origin && url.pathname === "/network/telemetry/", route => {
      const nodes = packet.models.hub.nodes.filter(node => node.kind !== "hub").map((node, index) => {
        const state = node.availability === "disabled" ? "disabled" : node.availability === "pending" ? "pending" : node.kind === "vless" ? "unsupported" : "active";
        const sampled = state === "active";
        return {id: node.id, state, source: sampled ? "awg" : "none", last_seen_at: sampled ? Math.floor(Date.now() / 1000) - 25 : null,
          rate_status: sampled ? "ok" : "unavailable", upload_bps: sampled ? (index + 1) * 1024 * 2 : null,
          download_bps: sampled ? (index + 1) * 1024 * 1024 * 99 : null};
      });
      return route.fulfill({status: 200, contentType: "application/json", body: JSON.stringify({schema_version: 1,
        sampled_at: new Date().toISOString(), refresh_ms: 2000, stale_after_ms: 8000, nodes})});
    });
    await page.goto(topologyURL);
    await hook(page, "graph").waitFor();
    page.on("request", request => {
      const item = {method: request.method(), url: request.url()};
      allRequests.push(item);
      if (isJSON(new URL(item.url))) requests.push(item);
      if (request.isNavigationRequest() && request.frame() === page.mainFrame()) navigations.push(request.url());
    });
    await Promise.all([page.waitForResponse(response => isJSON(new URL(response.url()))), hook(page, "refresh").click()]);
    await page.waitForFunction(() => document.querySelectorAll("[data-topology-node]").length === 12);
    await hook(page, "view-options").locator("summary").click();
    await hook(page, "reset").click();
    await hook(page, "view-options").locator("summary").click();
    const cardSizes = await hook(page, "node").evaluateAll(items => items.map(node => ({id: node.dataset.topologyNode, width: node.getBoundingClientRect().width, height: node.getBoundingClientRect().height})));
    async function inspect(model, direction, expected, theme, name) {
      try {
        const findings = await assertDirection(page, model, direction, expected);
        if (findings.length) report.layoutFindings.push({engine, width, theme, case: name, findings});
      }
      catch (error) {
        await peerStyles(page, engine, width, theme, name + "-failure");
        await capture(page, `${engine}-${width}-${theme}-${name}-failure.png`);
        throw error;
      }
      const actualSizes = await hook(page, "node").evaluateAll(items => items.map(node => ({id: node.dataset.topologyNode, width: node.getBoundingClientRect().width, height: node.getBoundingClientRect().height})));
      for (const actual of actualSizes) {
        const initial = cardSizes.find(node => node.id === actual.id);
        assert.ok(Math.abs(actual.width - initial.width) < .5, "card width stays fixed while height adapts to its visible contents");
      }
      await peerStyles(page, engine, width, theme, name);
      await capture(page, `${engine}-${width}-${theme}-${name}.png`);
    }
    const allModel = packet.models["vless:phone-all"], partialModel = packet.models["vless:phone-ports"], nasModel = packet.models["vless:phone-nas"], hubModel = packet.models.hub, nasTargetModel = packet.models["awg:nas-primary"];
    const details = hook(page, "full-details");
    for (const theme of ["light", "dark", "sky"]) {
      await setTheme(page, width, theme);
      await overview(page, allModel, requests);
      await capture(page, `${engine}-${width}-${theme}-overview.png`);
      await select(page, allModel.selected_id);
      await inspect(allModel, "forward", 8, theme, "phone-all-forward");
      assert.equal(await hook(page, "edge").count(), 1, "all-access phone has one VPS arrow, not eight crossing permission paths");
      assert.equal(await hook(page, "graph").locator(".is-peer").count(), 8, "all eight authorized targets remain framed");
      assert.equal(await hook(page, "inspector").locator("[data-topology-access-target]").count(), 8);
      assert.ok(allModel.links.filter(link => link.source === allModel.selected_id).every(link => link.scopes.length === 1 && link.scopes[0] === "全部协议 · 全部端口"));
      await inspect(allModel, "reverse", 0, theme, "phone-all-reverse");
      await overview(page, allModel, requests);
      await select(page, partialModel.selected_id);
      await inspect(partialModel, "forward", 1, theme, "phone-hub-tcp-udp");
      const hubScopes = await hook(page, "inspector").locator('.topology-access-scopes li').allTextContents();
      assert.deepEqual(hubScopes, ["TCP · 22, 9080", "UDP · 53, 123"]);
      // A new partial target must replace, not accumulate with, the warm VPS frame.
      await select(page, nasModel.selected_id);
      await inspect(nasModel, "forward", 1, theme, "phone-nas-only");
      assert.equal(await hook(page, "edge").count(), 0, "NAS-only phone has no permission arrows while its target remains visible");
      assert.equal(await hook(page, "graph").locator(".is-peer").count(), 1);
      await select(page, hubModel.selected_id);
      const inboundCount = hubModel.links.filter(link => link.target === "hub").length;
      await inspect(hubModel, "reverse", inboundCount, theme, "hub-inbound");
      assert.equal(await hook(page, "edge").count(), inboundCount, "VPS reverse view retains every authorized leaf-to-VPS arrow");
      assert.equal(await hook(page, "graph").locator('.kind-vless.is-peer[data-topology-peer="inbound"]').count(), 2, "known VLESS sources receive purple inbound frames");
      await select(page, nasTargetModel.selected_id);
      await inspect(nasTargetModel, "reverse", 3, theme, "nas-inbound");
      assert.equal(await hook(page, "graph").locator('.kind-vless.is-peer[data-topology-peer="inbound"]').count(), 2, "a sparse reverse view independently verifies both purple source frames");
      await overview(page, hubModel, requests);
      await capture(page, `${engine}-${width}-${theme}-overview-cleared.png`);
    }

    await select(page, allModel.selected_id);
    await assertDirection(page, allModel, "reverse", 0);
    await details.locator("summary").click();
    const reverseStatuses = await hook(page, "inbound").locator("[data-relation-status]").evaluateAll(items => items.map(item => item.dataset.relationStatus));
    assert.equal(reverseStatuses.length, 11);
    assert.ok(reverseStatuses.every(status => status === "not_applicable"), "every inbound relationship to a VLESS entry is not applicable, not falsely allowed");
    await details.locator("summary").click();

    missingContext = true;
    await Promise.all([page.waitForResponse(response => isJSON(new URL(response.url()))), hook(page, "refresh").click()]);
    await settle(page);
    await assertDirection(page, packet.missing_context, "forward", 0);
    await details.locator("summary").click();
    assert.match(await hook(page, "outbound").innerText(), /待核实|未提供|无法核实/);
    await details.locator("summary").click();
    await capture(page, `${engine}-${width}-missing-facts.png`);
    assert.deepEqual(navigations, [], "inspecting permissions never navigates away or sends a management operation");
    assert.ok(requests.length > 0 && requests.every(request => request.method === "GET" && isJSON(new URL(request.url))));
    assert.ok(allRequests.every(request => request.method === "GET" && (isJSON(new URL(request.url)) || new URL(request.url).pathname === "/network/telemetry/")), "configuration and telemetry remain exclusively read-only and no unrelated endpoint is called");
    assert.doesNotMatch(await hook(page, "root").innerHTML(), /synthetic-topology-private-credential-never-render|vless:\/\/|Preview-only-2026/);
    report.requests.push({engine, width, topologyGETs: requests.length});
    report.checks.push(`${engine} ${width}: real backend permissions, exact type-colored peers and current marker, inline protocol/port scopes with no floating labels or card overlap even for dense hub inbound, three themes, direction/overview/selection cleanup, GET-only and no credentials`);
  } finally { await context.close(); }
}

(async () => {
  try {
    for (const [engine, factory] of [["chromium", chromium], ["webkit", webkit]]) {
      const browser = await factory.launch();
      try {
        const anonymous = await browser.newContext();
        try {
          const response = await anonymous.request.get(topologyURL + "?format=json", {maxRedirects: 0});
          assert.ok([302, 401, 403].includes(response.status()), "topology requires authentication");
        } finally { await anonymous.close(); }
        for (const width of [1440, 320, 390]) await scenario(browser, engine, width);
      } finally { await browser.close(); }
    }
    assert.deepEqual(report.errors, []);
    assert.deepEqual(report.external, []);
    console.log(JSON.stringify({directory, checks: report.checks, screenshots: report.screenshots.length,
      peerStyleCases: report.peerStyles.length, layoutFindings: report.layoutFindings,
      requests: report.requests, errors: report.errors, external: report.external}, null, 2));
  } catch (error) {
    report.failure = error.stack;
    process.exitCode = 1;
    console.error(error.stack);
  } finally {
    fs.writeFileSync(path.join(directory, "report.json"), JSON.stringify(report, null, 2));
    console.log(`Topology permission artifacts: ${directory}`);
  }
})();
