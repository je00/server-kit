"use strict";

// Local-only regression using models projected by the real Python backend.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {spawnSync} = require("node:child_process");
const {chromium, webkit} = require("playwright");
const base = new URL(process.argv[2] || "http://127.0.0.1:8808/");
assert.ok(base.protocol === "http:" && ["localhost", "127.0.0.1"].includes(base.hostname)
  && !base.username && !base.password && base.pathname === "/", "only an isolated loopback preview is allowed");
const fixtureFile = path.join(__dirname, "test_topology_permissions_fixture.py");
const projected = spawnSync(process.env.TOPOLOGY_TEST_PYTHON || "python3", [fixtureFile, "--json"], {encoding: "utf8", maxBuffer: 4 * 1024 * 1024});
assert.equal(projected.status, 0, projected.stderr || "Python projection failed");
const packet = JSON.parse(projected.stdout);
assert.equal(packet.generated_by, "dashboard.topology.build_topology");
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "server-kit-topology-permissions-"));
const report = {directory, projector: packet.generated_by, checks: [], screenshots: [], requests: [], errors: [], external: []};
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
    await Promise.all([page.waitForResponse(response => isJSON(new URL(response.url()))), hook(page, "select").selectOption(id)]);
  }
  await settle(page);
}

async function assertDirection(page, model, direction, expectedCount) {
  await page.locator(`button[data-topology-direction="${direction}"]`).click();
  await settle(page);
  const expected = model.links.filter(link => direction === "forward" ? link.source === model.selected_id : link.target === model.selected_id);
  assert.equal(expected.length, expectedCount, "the real backend produced the expected number of confirmed directions");
  assert.equal(await hook(page, "node").count(), 12, "all twelve nodes remain on one canvas");
  const paths = await hook(page, "edge").evaluateAll(edges => edges.map(edge => ({source: edge.dataset.source, target: edge.dataset.target,
    dash: getComputedStyle(edge).strokeDasharray, marker: edge.getAttribute("marker-end"), bidirectional: edge.dataset.bidirectional})));
  assert.deepEqual(paths.map(link => `${link.source}→${link.target}`).sort(), expected.map(link => `${link.source}→${link.target}`).sort());
  assert.ok(paths.every(edge => edge.marker && edge.bidirectional !== "true" && edge.dash !== "none"), "confirmed permissions are dashed, directed, and never reversed");
  const rows = await hook(page, "inspector").locator("[data-topology-access-target]").evaluateAll(items => items.map(item => ({id: item.dataset.topologyAccessTarget,
    scopes: [...item.querySelectorAll(".topology-access-scopes li")].map(scope => scope.textContent)})));
  assert.deepEqual(rows.sort((a, b) => a.id.localeCompare(b.id)), expected.map(link => ({id: direction === "forward" ? link.target : link.source, scopes: link.scopes})).sort((a, b) => a.id.localeCompare(b.id)),
    "the visible inspector contains every exact backend scope and no additional access");
  assert.equal(await hook(page, "edge-label").count(), expectedCount);
  const bounds = await hook(page, "graph").evaluate(graph => {
    const box = graph.getBoundingClientRect();
    const labels = [...graph.querySelectorAll("[data-topology-edge-label]")];
    const cards = [...graph.querySelectorAll("[data-topology-node]")].map(node => node.getBoundingClientRect());
    return labels.map(label => {
      const rect = label.getBoundingClientRect();
      return {key: label.dataset.linkKey, clipped: rect.left < box.left - 1 || rect.right > box.right + 1 || rect.top < box.top - 1 || rect.bottom > box.bottom + 1,
        behindCard: cards.some(card => Math.min(card.right, rect.right) - Math.max(card.left, rect.left) > 1 && Math.min(card.bottom, rect.bottom) - Math.max(card.top, rect.top) > 1)};
    });
  });
  assert.ok(bounds.every(label => !label.clipped && !label.behindCard), `port labels remain completely visible: ${JSON.stringify(bounds.filter(label => label.clipped || label.behindCard))}`);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
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
  const requests = [], navigations = [];
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
    await page.goto(topologyURL);
    await hook(page, "graph").waitFor();
    page.on("request", request => {
      requests.push({method: request.method(), url: request.url()});
      if (request.isNavigationRequest() && request.frame() === page.mainFrame()) navigations.push(request.url());
    });
    await Promise.all([page.waitForResponse(response => isJSON(new URL(response.url()))), hook(page, "refresh").click()]);
    await page.waitForFunction(() => document.querySelectorAll("[data-topology-node]").length === 12);
    await hook(page, "view-options").locator("summary").click();
    await hook(page, "reset").click();
    await hook(page, "view-options").locator("summary").click();
    assert.equal(await hook(page, "edge").count(), 0, "the default overview still contains no permission edges");
    await capture(page, `${engine}-${width}-overview.png`);

    await select(page, "vless:phone-all");
    const allModel = packet.models["vless:phone-all"];
    await assertDirection(page, allModel, "forward", 8);
    assert.ok(allModel.links.filter(link => link.source === allModel.selected_id).every(link => link.scopes.length === 1 && link.scopes[0] === "全部协议 · 全部端口"));
    await capture(page, `${engine}-${width}-phone-all-forward.png`);
    await assertDirection(page, allModel, "reverse", 0);
    const details = hook(page, "full-details");
    await details.locator("summary").click();
    const reverseStatuses = await hook(page, "inbound").locator("[data-relation-status]").evaluateAll(items => items.map(item => item.dataset.relationStatus));
    assert.equal(reverseStatuses.length, 11);
    assert.ok(reverseStatuses.every(status => status === "not_applicable"), "every inbound relationship to a VLESS entry is not applicable, not falsely allowed");
    await details.locator("summary").click();
    await capture(page, `${engine}-${width}-phone-all-reverse.png`);

    await select(page, "vless:phone-ports");
    await assertDirection(page, packet.models["vless:phone-ports"], "forward", 1);
    const hubScopes = await hook(page, "inspector").locator('.topology-access-scopes li').allTextContents();
    assert.deepEqual(hubScopes, ["TCP · 22, 9080", "UDP · 53, 123"]);
    await capture(page, `${engine}-${width}-phone-hub-tcp-udp.png`);

    missingContext = true;
    await select(page, "vless:phone-all");
    await assertDirection(page, packet.missing_context, "forward", 0);
    await details.locator("summary").click();
    assert.match(await hook(page, "outbound").innerText(), /待核实|未提供|无法核实/);
    await details.locator("summary").click();
    await capture(page, `${engine}-${width}-missing-facts.png`);
    assert.deepEqual(navigations, [], "inspecting permissions never navigates away or sends a management operation");
    assert.ok(requests.length > 0 && requests.every(request => request.method === "GET" && isJSON(new URL(request.url))));
    assert.doesNotMatch(await hook(page, "root").innerHTML(), /synthetic-topology-private-credential-never-render|vless:\/\/|Preview-only-2026/);
    report.requests.push({engine, width, topologyGETs: requests.length});
    report.checks.push(`${engine} ${width}: twelve nodes; phone all gives eight full-scope directions, reverse has eleven not-applicable results and no edges, explicit hub TCP/UDP remains exact, absent facts remain unconfirmed, GET-only and no credentials`);
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
        for (const width of [320, 390, 1440]) await scenario(browser, engine, width);
      } finally { await browser.close(); }
    }
    assert.deepEqual(report.errors, []);
    assert.deepEqual(report.external, []);
    console.log(JSON.stringify(report, null, 2));
  } catch (error) {
    report.failure = error.stack;
    process.exitCode = 1;
    console.error(error.stack);
  } finally {
    fs.writeFileSync(path.join(directory, "report.json"), JSON.stringify(report, null, 2));
    console.log(`Topology permission artifacts: ${directory}`);
  }
})();
