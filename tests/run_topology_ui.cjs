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
const report = {directory, checks: [], screenshots: [], errors: [], blocked: []};
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
  return {...original, nodes, selected, selected_id: selected.id,
    relations: nodes.filter(node => node.id !== selected.id).map(node => ({node, forward: {...allowed}, reverse: {...allowed}, relation: "mutual", label: "双向可访问"})),
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
  // The native select remains available even when graph pagination hides a node.
  await hook(page, "select").selectOption(id);
}

async function assertStar(page) {
  // Read one atomic frame: ResizeObserver may repaginate between tool calls.
  const {nodes, selectedId, lines, geometry} = await hook(page, "graph").evaluate(graph => {
    const nodeElements = [...graph.querySelectorAll("[data-topology-node]")];
    const edgeElements = [...graph.querySelectorAll("[data-topology-edge]")];
    const nodes = nodeElements.map(node => ({id: node.dataset.topologyNode, tag: node.tagName, pressed: node.getAttribute("aria-pressed")}));
    const selectedId = document.querySelector("[data-topology-select]").value;
    const lines = edgeElements.map(edge => ({tag: edge.tagName.toLowerCase(), source: edge.dataset.source, target: edge.dataset.target,
      start: edge.getAttribute("marker-start"), end: edge.getAttribute("marker-end")}));
    const buttons = new Map(nodeElements.map(node => [node.dataset.topologyNode, node.getBoundingClientRect()]));
    const hub = buttons.get("hub");
    const overlappingHub = [...buttons].filter(([id, box]) => id !== "hub" && box.left < hub.right && box.right > hub.left && box.top < hub.bottom && box.bottom > hub.top).map(([id]) => id);
    const reversed = edgeElements.filter(edge => {
      const from = buttons.get(edge.dataset.source), to = buttons.get(edge.dataset.target);
      const dx = (to.left + to.width / 2) - (from.left + from.width / 2);
      const dy = (to.top + to.height / 2) - (from.top + from.height / 2);
      return (Number(edge.getAttribute("x2")) - Number(edge.getAttribute("x1"))) * dx +
        (Number(edge.getAttribute("y2")) - Number(edge.getAttribute("y1"))) * dy <= 0;
    }).map(edge => edge.dataset.source);
    return {nodes, selectedId, lines, geometry: {overlappingHub, reversed}};
  });
  assert.equal(nodes.filter(node => node.id === "hub").length, 1, "one central VPS");
  assert.ok(nodes.every(node => node.tag === "BUTTON"), "graph nodes are keyboard-operable buttons");
  assert.equal(nodes.filter(node => node.pressed === "true").length, nodes.some(node => node.id === selectedId) ? 1 : 0,
    "a visible selected node is marked without changing a selection hidden by search/pagination");
  assert.equal(lines.length, nodes.length - 1, "one physical spoke for every visible client");
  const ids = new Set(nodes.map(node => node.id));
  for (const line of lines) {
    assert.ok(["line", "path"].includes(line.tag), "edges are SVG geometry");
    assert.ok((line.source === "hub") !== (line.target === "hub"), "every physical edge touches the VPS; never client-to-client");
    assert.ok(ids.has(line.source) && ids.has(line.target), "edge endpoints belong to visible graph nodes");
    if (line.source.startsWith("vless:")) assert.ok(!line.start && line.end, "VLESS shows only its outbound spoke direction");
  }
  assert.deepEqual(geometry.overlappingHub, [], "client cards must not overlap the VPS card");
  assert.deepEqual(geometry.reversed, [], "visible spoke endpoints must proceed from the client toward the VPS, never fold under their cards");
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
  };
}

async function responsiveThemes(browser, label, width) {
  const state = await session(browser, width);
  const {page, context} = state;
  try {
    await assertStar(page);
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
      await assertStar(page);
      await screenshot(page, `${label}-${width}-${theme}`);
      if (theme === "light") {
        const name = `${label}-${width}-graph.png`;
        await hook(page, "graph").screenshot({path: path.join(directory, name)});
        report.screenshots.push(name);
      }
    }
    await assertReadOnly(state);
    report.checks.push(`${label} ${width}: central VPS spokes, touch/click selection, three themes, no overflow or navigation`);
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
    await assertStar(page);
    await screenshot(page, `${label}-refresh-error`);
    await page.unroute(jsonRoute);
    await page.route(jsonRoute, route => route.fulfill({status: 200, contentType: "text/html", body: "<!doctype html><title>Login</title><form>synthetic expired session</form>"}));
    await Promise.all([page.waitForResponse(jsonResponse), hook(page, "refresh").click()]);
    await page.waitForFunction(() => !document.querySelector("[data-topology-refresh]").disabled);
    assert.deepEqual(await viewState(page), before, "expired login HTML cannot replace the last good view");
    assert.doesNotMatch(await hook(page, "root").innerHTML(), /synthetic expired session/);
    const missingKind = structuredClone(original);
    delete missingKind.nodes.find(node => node.kind === "awg").kind;
    for (const body of ["{bad json", JSON.stringify({nodes: [], selected_id: "hub"}), JSON.stringify(missingKind)]) {
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
    await Promise.all([page.waitForResponse(jsonResponse), hook(page, "refresh").click()]);
    await page.waitForFunction(() => document.querySelector("[data-topology-select]").options.length === 41);
    await assertStar(page);
    const firstPage = await hook(page, "node").allTextContents();
    await hook(page, "next").click();
    assert.notDeepEqual(await hook(page, "node").allTextContents(), firstPage);
    await hook(page, "prev").click();
    assert.deepEqual(await hook(page, "node").allTextContents(), firstPage);
    await hook(page, "search").fill("synthetic-39");
    assert.equal(await hook(page, "node").count(), 2, "search shows matching node plus VPS");
    await assertStar(page);
    await screenshot(page, `${label}-390-search-40-nodes`);
    await hook(page, "search").fill("no-synthetic-node-matches");
    assert.equal(await hook(page, "node").count(), 1, "empty search retains only the VPS");
    await hook(page, "search").fill("");
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
    await screenshot(page, `${label}-390-many-nodes`);
    await page.setViewportSize({width: 320, height: 844});
    await page.waitForTimeout(50);
    await assertStar(page);
    await screenshot(page, `${label}-320-many-nodes`);
    await page.setViewportSize({width: 768, height: 1000});
    await page.waitForTimeout(50);
    await assertStar(page);
    await screenshot(page, `${label}-768-many-nodes`);
    await page.setViewportSize({width: 1440, height: 1000});
    await page.waitForTimeout(50);
    await assertStar(page);
    await screenshot(page, `${label}-1440-many-nodes`);
    await assertReadOnly(state);
    report.checks.push(`${label}: 40-node search, pagination, mobile/desktop layout, and stale request protection`);
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
        if (!process.argv.includes("--keyboard-only")) {
          for (const width of [320, 390, 768, 1440]) await responsiveThemes(browser, label, width);
        }
        await keyboardAndErrors(browser, label);
        if (process.argv.includes("--keyboard-only")) continue;
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
