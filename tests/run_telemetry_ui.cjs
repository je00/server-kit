"use strict";

// Read-only, local-only UI regression: no production credentials or endpoints.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const {chromium, webkit} = require("playwright");
const {geometryFindings, inlineSnapshot} = require("./topology_inline_assertions.cjs");
const base = new URL(process.argv[2] || "http://127.0.0.1:8814/");
assert.ok(base.protocol === "http:" && ["localhost", "127.0.0.1"].includes(base.hostname) && base.pathname === "/" && !base.username && !base.password);
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "server-kit-telemetry-ui-"));
const report = {directory, checks: [], screenshots: [], errors: [], requests: []};
const source = fs.readFileSync(path.join(__dirname, "../web/static/node_telemetry.js"), "utf8");
const stamp = "2026-01-01T00:00:00.000Z";
const row = (id, state = "active", status = "ok", up = 2048, down = 3072) => ({id, state, last_seen_at: 1767225600, rate_status: status,
  upload_bps: status === "ok" ? up : null, download_bps: status === "ok" ? down : null, source: id.startsWith("awg:") ? "awg" : "none"});
const packet = (at = stamp, nodes = [row("awg:demo"), row("vless:phone", "unsupported", "unavailable")], age = 0) => ({schema_version: 1, sampled_at: at, sample_age_ms: age, refresh_ms: 2000, stale_after_ms: 8000, nodes});
const target = '[data-telemetry-node="awg:demo"]';
async function until(page, predicate) {
  for (let attempt = 0; attempt < 300; attempt++) {
    if (await page.evaluate(predicate)) return;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  throw new Error(`condition did not settle: ${predicate}\n${await page.locator("body").innerText()}\n${JSON.stringify(await page.evaluate(() => ({now:Date.now(),hidden:document.hidden})))}`);
}
const html = `<!doctype html><meta charset="utf-8"><main data-telemetry-url="/network/telemetry/"><span data-telemetry-update></span>
<details open id="form-state"><summary>Settings</summary><input value="keep me"></details>
${["awg:demo", "vless:phone"].map(id => `<div data-telemetry-node="${id}" data-telemetry-compact="true"><span data-telemetry-status><span data-telemetry-state-label></span></span><span data-telemetry-rates></span></div>`).join("")}</main><script src="/test-node-telemetry.js"></script>`;

async function pollTests(engine, browser) {
  const context = await browser.newContext(), page = await context.newPage();
  page.on("pageerror", error => report.errors.push(error.message));
  await page.clock.install({time: new Date(stamp)});
  await page.clock.pauseAt(new Date(stamp));
  let current = packet(), calls = 0, active = 0, peak = 0, held = null, fail = false, hold = false;
  await context.route("**/*", async route => {
    const url = new URL(route.request().url());
    assert.equal(url.origin, base.origin, "tests cannot contact an external host");
    if (url.pathname === "/test-node-telemetry.js") return route.fulfill({contentType: "text/javascript", body: source});
    if (url.pathname !== "/network/telemetry/") return route.fulfill({contentType: "text/html", body: html});
    assert.equal(route.request().method(), "GET");
    calls++; active++; peak = Math.max(peak, active);
    if (hold) { held = route; return; }
    await route.fulfill(fail ? {status: 503, contentType: "text/html", body: "Unavailable"} : {contentType: "application/json", body: JSON.stringify(current)});
    active--;
  });
  await page.goto(new URL("__telemetry_unit__", base).href);
  await until(page, () => document.querySelector("[data-telemetry-rates]").textContent === "↑2.0K ↓3.0K");
  assert.equal(calls, 1);
  assert.equal(await page.locator('[data-telemetry-node="vless:phone"] [data-telemetry-state-label]').innerText(), "未开启");
  assert.equal(await page.locator('[data-telemetry-node="vless:phone"] [data-telemetry-rates]').innerText(), "↑— ↓—");
  await page.evaluate(() => { window.originalNode = document.querySelector('[data-telemetry-node="awg:demo"]'); });
  const advance = async (ms = 2000) => { const before = calls; await page.clock.runFor(ms); await new Promise(resolve => setTimeout(resolve, 50)); return calls - before; };
  current = packet("2026-01-01T00:00:02.000Z", [row("awg:demo", "recent", "ok", 0, 0), row("vless:phone", "unsupported", "unavailable")]);
  await advance(); await until(page, () => document.querySelector("[data-telemetry-rates]").textContent === "↑0B ↓0B");
  assert.equal(await page.locator(`${target} [data-telemetry-state-label]`).innerText(), "近期握手");
  assert.equal(await page.evaluate(() => originalNode === document.querySelector('[data-telemetry-node="awg:demo"]')), true, "rate updates do not replace node DOM");
  assert.equal(await page.locator("#form-state").getAttribute("open"), "");
  assert.equal(await page.locator("#form-state input").inputValue(), "keep me");
  report.checks.push(`${engine}: accurate direction, genuine zero, unsupported VLESS, stable DOM and forms`);

  current = packet("2026-01-01T00:00:04.000Z", [row("awg:demo", "recent", "warming_up")]);
  await advance(); await until(page, () => document.querySelector("[data-telemetry-state-label]").textContent === "采样中");
  assert.equal(await page.locator(`${target} [data-telemetry-rates]`).innerText(), "↑— ↓—");
  current = packet("2026-01-01T00:00:06.000Z", [row("awg:demo", "recent", "reset")]);
  await advance(); await until(page, () => document.querySelector("[data-telemetry-state-label]").textContent === "重新采样");
  current = packet("2026-01-01T00:00:08.000Z");
  await advance(); await until(page, () => document.querySelector("[data-telemetry-rates]").textContent === "↑2.0K ↓3.0K");
  current = packet("2026-01-01T00:00:10.000Z"); current.nodes[0].upload_bps = -1;
  await advance(); await until(page, () => document.querySelector("[data-telemetry-update]").dataset.state === "retrying");
  assert.equal(await page.locator(`${target} [data-telemetry-rates]`).innerText(), "↑2.0K ↓3.0K", "invalid packet preserves the last sample");
  current = packet("2025-12-31T23:59:00.000Z");
  await advance(4000);
  await page.clock.runFor(2100);
  assert.equal(await page.locator(`${target} [data-telemetry-state-label]`).innerText(), "已过期");
  assert.equal(await page.locator(`${target} [data-telemetry-rates]`).innerText(), "↑— ↓—", "old data cannot masquerade as current zero or rates");
  report.checks.push(`${engine}: warm-up/reset, malformed and out-of-order packets, stale after eight seconds`);

  const beforeHidden = calls;
  await page.evaluate(() => { Object.defineProperty(document, "hidden", {configurable: true, value: true}); document.dispatchEvent(new Event("visibilitychange")); });
  await page.clock.runFor(60000);
  assert.equal(calls, beforeHidden, "hidden page stops polling");
  current = packet("2026-01-01T00:01:30.000Z");
  await page.evaluate(() => { Object.defineProperty(document, "hidden", {configurable: true, value: false}); document.dispatchEvent(new Event("visibilitychange")); });
  await until(page, () => document.querySelector("[data-telemetry-update]").dataset.state === "ready");
  assert.equal(calls, beforeHidden + 1, "visible page samples immediately");
  hold = true;
  await page.clock.runFor(2000); await page.waitForTimeout(50);
  assert.ok(held);
  const heldCalls = calls;
  await page.clock.runFor(4000);
  assert.equal(calls, heldCalls, "no overlapping request while one is pending");
  await page.clock.runFor(1100);
  await until(page, () => document.querySelector("[data-telemetry-update]").dataset.state === "retrying");
  await held.fulfill({contentType: "application/json", body: JSON.stringify(packet("2026-01-01T02:00:00.000Z", [row("awg:demo", "active", "ok", 999999, 999999)]))}).catch(() => {});
  active--; held = null; hold = false;
  assert.ok(!(await page.locator(`${target} [data-telemetry-rates]`).innerText()).includes("977"), "aborted late reply cannot overwrite");
  fail = true;
  await page.clock.runFor(4000); await page.waitForTimeout(50);
  const afterFail = calls;
  await page.clock.runFor(7000);
  assert.equal(calls, afterFail, "failure retries back off rather than pile up");
  report.checks.push(`${engine}: hidden pause/resume, five-second timeout, single flight, retry backoff, stale late reply rejected`);
  fail = false;
  current = packet(new Date(await page.evaluate(() => Date.now()) - 30000).toISOString(), undefined, 30000);
  await page.goto(new URL("__telemetry_unit__?old-first", base).href);
  await until(page, () => document.querySelector("[data-telemetry-update]").dataset.state === "stale");
  assert.equal(await page.locator(`${target} [data-telemetry-rates]`).innerText(), "↑— ↓—", "old first packet is stale immediately");
  current = packet(new Date(await page.evaluate(() => Date.now())).toISOString());
  await page.goto(new URL("__telemetry_unit__?same-time", base).href);
  await until(page, () => document.querySelector("[data-telemetry-update]").dataset.state === "ready");
  for (let index = 0; index < 4; index++) await advance();
  assert.equal(await page.locator(`${target} [data-telemetry-state-label]`).innerText(), "已过期", "repeated server timestamp never extends freshness");
  current = packet(new Date(await page.evaluate(() => Date.now()) + 60000).toISOString());
  await page.goto(new URL("__telemetry_unit__?future", base).href);
  await until(page, () => document.querySelector("[data-telemetry-update]").dataset.state === "ready");
  assert.equal(await page.locator(`${target} [data-telemetry-rates]`).innerText(), "↑2.0K ↓3.0K", "a server timestamp ahead of the device is not a clock-health verdict");
  for (let index = 0; index < 4; index++) await advance();
  assert.equal(await page.locator(`${target} [data-telemetry-state-label]`).innerText(), "已过期", "future-looking wall time cannot make a repeated sample permanently fresh");
  const invalidNodes = [row("awg:bad/path"), {...row("awg:demo"), upload_bps: 1e16}, {...row("awg:demo"), source: "xray"}, {...row("awg:demo"), state: "disabled"}];
  for (const [index, node] of invalidNodes.entries()) {
    current = packet(new Date(await page.evaluate(() => Date.now())).toISOString(), [node]);
    await page.goto(new URL(`__telemetry_unit__?invalid=${index}`, base).href);
    await until(page, () => document.querySelector("[data-telemetry-update]").dataset.state === "retrying");
    assert.equal(await page.locator(`${target} [data-telemetry-rates]`).innerText(), "↑— ↓—");
  }
  const invalidAges = [-1, 0.5, 86400001, null, "0", true, Infinity, undefined];
  for (const [index, age] of invalidAges.entries()) {
    current = {...packet(new Date(await page.evaluate(() => Date.now())).toISOString()), sample_age_ms: age};
    if (age === undefined) delete current.sample_age_ms;
    await page.goto(new URL(`__telemetry_unit__?invalid-age=${index}`, base).href);
    await until(page, () => document.querySelector("[data-telemetry-update]").dataset.state === "retrying");
    assert.equal(await page.locator(`${target} [data-telemetry-rates]`).innerText(), "↑— ↓—", `invalid age ${String(age)} is not treated as fresh zero`);
  }
  report.checks.push(`${engine}: server-aged old first sample, duplicate timestamp expiry, clock-offset tolerance and invalid age/identity/rates rejected`);
  report.requests.push({engine, unitGETs: calls, peak});
  await context.close();
}

async function clockTests(engine, browser) {
  for (const offset of [-300000, 300000]) {
    const context = await browser.newContext(), page = await context.newPage();
    page.on("pageerror", error => report.errors.push(error.message));
    const browserTime = new Date(Date.parse(stamp) + offset);
    await page.clock.install({time: browserTime}); await page.clock.pauseAt(browserTime);
    let current = packet(), calls = 0, held = null, hold = false;
    await context.route("**/*", async route => {
      const url = new URL(route.request().url()); assert.equal(url.origin, base.origin);
      if (url.pathname === "/test-node-telemetry.js") return route.fulfill({contentType: "text/javascript", body: source});
      if (url.pathname !== "/network/telemetry/") return route.fulfill({contentType: "text/html", body: html});
      assert.equal(route.request().method(), "GET"); calls++;
      if (hold) { held = route; return; }
      return route.fulfill({contentType: "application/json", body: JSON.stringify(current)});
    });
    await page.goto(new URL(`__telemetry_unit__?clock=${offset}`, base).href);
    await until(page, () => document.querySelector("[data-telemetry-update]").dataset.state === "ready");
    assert.equal(await page.locator(`${target} [data-telemetry-rates]`).innerText(), "↑2.0K ↓3.0K", "a device five minutes ahead or behind must show a new sample");
    for (const [index, jump] of [86400000, -86400000].entries()) {
      const monotonicBefore = await page.evaluate(() => performance.now());
      await page.clock.setSystemTime(new Date(Date.parse(stamp) + jump));
      assert.equal(await page.evaluate(() => performance.now()), monotonicBefore, "the test changes wall time without aging the sample");
      current = packet(new Date(Date.parse(stamp) + (index + 1) * 2000).toISOString(), [row("awg:demo", "active", "ok", (index + 3) * 1024, (index + 4) * 1024)]);
      await page.clock.runFor(2000);
      const expected = `↑${index + 3}.0K ↓${index + 4}.0K`;
      await until(page, () => document.querySelector("[data-telemetry-update]").dataset.state === "ready");
      for (let attempt = 0; attempt < 200 && await page.locator(`${target} [data-telemetry-rates]`).innerText() !== expected; attempt++) await new Promise(resolve => setTimeout(resolve, 10));
      assert.equal(await page.locator(`${target} [data-telemetry-rates]`).innerText(), expected, "a live device clock change cannot reject or expire a fresh sample");
    }
    report.checks.push(`${engine}: browser clock ${offset / 60000} minutes, then ±24-hour live wall-clock changes, remain fresh`);

    current = packet(stamp, undefined, 8000);
    await page.goto(new URL("__telemetry_unit__?server-age-boundary", base).href);
    await until(page, () => document.querySelector("[data-telemetry-update]").dataset.state === "stale");
    assert.equal(await page.locator(`${target} [data-telemetry-rates]`).innerText(), "↑— ↓—", "an actual eight-second-old first packet is stale regardless of device time");
    current = packet(stamp, undefined, 6500); hold = true;
    await page.goto(new URL("__telemetry_unit__?delayed-old", base).href);
    for (let attempt = 0; !held && attempt < 200; attempt++) await new Promise(resolve => setTimeout(resolve, 10));
    assert.ok(held, "a delayed response is in flight");
    await page.clock.runFor(2000);
    await held.fulfill({contentType: "application/json", body: JSON.stringify(current)}); held = null; hold = false;
    await until(page, () => document.querySelector("[data-telemetry-update]").dataset.state === "stale");
    assert.equal(await page.locator(`${target} [data-telemetry-rates]`).innerText(), "↑— ↓—", "server age plus request transit time crosses the freshness limit");

    current = packet(stamp, undefined, 6500);
    await page.goto(new URL("__telemetry_unit__?remaining-lifetime", base).href);
    await until(page, () => document.querySelector("[data-telemetry-update]").dataset.state === "ready");
    await page.clock.runFor(1499);
    assert.equal(await page.locator("[data-telemetry-update]").getAttribute("data-state"), "ready");
    await page.clock.runFor(2);
    assert.equal(await page.locator("[data-telemetry-update]").getAttribute("data-state"), "stale", "only the remaining 1.5 seconds of freshness are granted");
    current = packet(stamp);
    await page.goto(new URL("__telemetry_unit__?same-time-age-grows", base).href);
    await until(page, () => document.querySelector("[data-telemetry-update]").dataset.state === "ready");
    current = packet(stamp, undefined, 8000);
    await page.clock.runFor(2000);
    await until(page, () => document.querySelector("[data-telemetry-update]").dataset.state === "stale");
    assert.equal(await page.locator(`${target} [data-telemetry-rates]`).innerText(), "↑— ↓—", "an increased authoritative age for the same timestamp must shorten freshness, never revive it");
    report.checks.push(`${engine}: clock ${offset / 60000} minutes does not hide old server age, delayed transit, or remaining monotonic lifetime`);
    report.requests.push({engine, clockOffsetMs: offset, clockGETs: calls});
    await context.close();
  }
}

async function integration(engine, browser, width) {
  const context = await browser.newContext({viewport: {width, height: 900}, ...(width < 768 ? {isMobile: true, hasTouch: true} : {})});
  await context.route("**/*", route => new URL(route.request().url()).origin === base.origin ? route.continue() : route.abort());
  const page = await context.newPage(); page.on("pageerror", error => report.errors.push(error.message));
  await page.goto(new URL("login/", base).href);
  await page.locator('[name="username"]').fill("preview"); await page.locator('[name="password"]').fill("Preview-only-2026!");
  await Promise.all([page.waitForURL(base.href), page.locator('button[type="submit"]').click()]);
  assert.equal((await context.request.get(new URL("__preview__/scenario/rich/", base).href)).status(), 200);
  await page.goto(new URL("network/topology/", base).href);
  await page.waitForFunction(() => document.querySelector("[data-telemetry-update]").dataset.state === "ready");
  await page.waitForFunction(() => [...document.querySelectorAll('[data-topology-node^="awg:"] [data-telemetry-rates]')].some(node => !node.textContent.includes("—")));
  assert.match(await page.locator('[data-topology-node^="awg:"] [data-telemetry-rates]').first().innerText(), /↑\d/);
  report.checks.push(`${engine}/${width}: unmocked authenticated preview telemetry accepted and AWG rates displayed`);
  let count = 0, nodes = [];
  await context.route("**/network/telemetry/", async route => {
    count++;
    await route.fulfill({contentType: "application/json", body: JSON.stringify(packet(new Date().toISOString(), nodes.map((node, index) =>
      node.availability === "disabled" ? row(node.id, "disabled", "unavailable") : node.kind === "vless" ? row(node.id, "unsupported", "unavailable") : row(node.id, index % 2 ? "recent" : "active", "ok", index * 1024, (index + 1) * 18000))))});
  });
  await page.goto(new URL("network/topology/", base).href);
  nodes = await page.locator("#topology-data").evaluate(node => JSON.parse(node.textContent).nodes.filter(item => item.kind !== "hub"));
  await page.waitForFunction(() => document.querySelector('[data-topology-node][data-telemetry-node] [data-telemetry-state-label]').textContent !== "暂无数据");
  await page.waitForTimeout(2200);
  const before = await page.locator("[data-topology-node]").evaluateAll(items => { window.savedGraphNodes = items; return items.map(node => [node.dataset.topologyNode, node.dataset.worldX, node.dataset.worldY]); });
  await page.waitForTimeout(2200);
  assert.deepEqual(await page.locator("[data-topology-node]").evaluateAll(items => items.map(node => [node.dataset.topologyNode, node.dataset.worldX, node.dataset.worldY])), before);
  assert.equal(await page.evaluate(() => savedGraphNodes.every(node => node.isConnected)), true, "telemetry leaves cards and positions intact");
  assert.equal(await page.locator('[data-topology-node="hub"] [data-telemetry-rates]').count(), 0, "VPS never mislabels AWG subtotal as total");
  assert.equal(await page.locator("[data-topology-graph]").evaluate(node => getComputedStyle(node).touchAction), "pan-y pinch-zoom");
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
  const sizes = await page.locator('[data-topology-node][data-telemetry-node]').evaluateAll(items => items.map(node => ({height: node.offsetHeight,
    clippedRate: node.querySelector('[data-telemetry-rates]').scrollWidth > node.querySelector('[data-telemetry-rates]').clientWidth + 1})));
  assert.ok(sizes.every(size => size.height === 72 && !size.clippedRate), "rates use one compact row without clipping");
  await page.screenshot({path: path.join(directory, `${engine}-${width}-topology.png`), fullPage: true, style: ".skip-link:not(:focus){visibility:hidden!important}"});
  report.screenshots.push(`${engine}-${width}-topology.png`);
  const models = new Map();
  for (const node of nodes.slice(0, 3)) {
    const url = new URL("network/topology/", base); url.searchParams.set("format", "json"); url.searchParams.set("node", node.id);
    const response = await context.request.get(url.href); assert.equal(response.status(), 200); models.set(node.id, await response.json());
  }
  let configRequests = 0, denyId = null, changed = false;
  await context.route(url => url.pathname === "/network/topology/" && url.searchParams.get("format") === "json", async route => {
    configRequests++;
    const id = new URL(route.request().url()).searchParams.get("node");
    if (id === denyId) return route.fulfill({status: 503, contentType: "text/html", body: "Unavailable"});
    const model = structuredClone(models.get(id));
    if (changed) {
      for (const link of model.links) { link.scopes = ["TCP · 8443"]; link.label = "TCP · 8443"; }
      for (const relation of model.relations) for (const key of ["forward", "reverse"]) if (["allowed", "partial"].includes(relation[key].status)) {
        relation[key].scopes = ["TCP · 8443"]; relation[key].label = "TCP · 8443";
      }
    }
    return route.fulfill({contentType: "application/json", body: JSON.stringify(model)});
  });
  const pick = async id => {
    await page.locator("[data-topology-select]").selectOption(id);
    await page.waitForFunction(value => document.querySelector(`[data-topology-node="${value}"]`).getAttribute("aria-pressed") === "true" && !document.querySelector("[data-topology-root]").hasAttribute("aria-busy"), id);
  };
  const [firstId, secondId, thirdId] = [...models.keys()];
  await pick(firstId); await pick(secondId); const initialCount = configRequests;
  assert.deepEqual(geometryFindings(await inlineSnapshot(page)), [], "selected marker, status and permission scopes do not collide");
  await page.evaluate(() => { document.documentElement.dataset.theme = "dark"; document.activeElement?.blur(); });
  await page.waitForTimeout(400);
  await page.screenshot({path: path.join(directory, `${engine}-${width}-selected-dark.png`), fullPage: true, style: ".skip-link:not(:focus){visibility:hidden!important}"});
  report.screenshots.push(`${engine}-${width}-selected-dark.png`);
  await page.evaluate(() => { document.documentElement.dataset.theme = "light"; });
  await pick(firstId); assert.equal(configRequests, initialCount, "recent selections reuse a validated per-selection permission snapshot");
  changed = true;
  await page.locator("[data-topology-refresh]").click();
  await page.waitForFunction(() => !document.querySelector("[data-topology-root]").hasAttribute("aria-busy"));
  assert.equal(configRequests, initialCount + 1, "manual refresh always bypasses cache");
  await pick(secondId);
  assert.equal(configRequests, initialCount + 2, "changed permission links invalidate cached alternate directions/selections");
  assert.ok((await page.locator("[data-topology-inspector]").innerText()).includes("8443"));
  denyId = thirdId;
  await page.locator("[data-topology-select]").selectOption(thirdId);
  await page.waitForFunction(() => document.querySelector("[data-topology-status]").dataset.state === "error");
  const afterError = configRequests; denyId = null;
  await pick(thirdId); assert.equal(configRequests, afterError + 1, "failed selections are never cached");
  report.checks.push(`${engine}/${width}: 30-second selected-snapshot cache, refresh bypass, configuration invalidation, errors not cached`);
  await page.goto(new URL("network/nodes/", base).href);
  await page.locator('.network-node-card[data-telemetry-node]').first().waitFor();
  const first = page.locator('.network-node-card[data-telemetry-node]').first(); await first.locator("summary").first().click();
  await page.waitForTimeout(2300);
  assert.equal(await first.getAttribute("open"), "");
  assert.ok((await first.locator("[data-telemetry-rates]").innerText()).includes("/s"));
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
  await page.screenshot({path: path.join(directory, `${engine}-${width}-nodes.png`), fullPage: true, style: ".skip-link:not(:focus){visibility:hidden!important}"});
  report.screenshots.push(`${engine}-${width}-nodes.png`);
  report.checks.push(`${engine}/${width}: real templates, compact cards, mobile touch contract, stable graph, list form disclosure`);
  report.requests.push({engine, integrationGETs: count}); await context.close();
}

(async () => {
  for (const [name, engine, width] of [["chromium", chromium, 1440], ["webkit", webkit, 390]]) {
    const browser = await engine.launch();
    try { await pollTests(name, browser); await clockTests(name, browser); if (!process.env.TELEMETRY_UNIT_ONLY) await integration(name, browser, width); }
    finally { await browser.close(); }
  }
  assert.deepEqual(report.errors, []);
  fs.writeFileSync(path.join(directory, "report.json"), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report, null, 2));
})().catch(error => { report.errors.push(error.stack); fs.writeFileSync(path.join(directory, "report.json"), JSON.stringify(report, null, 2)); console.error(error); console.error(directory); process.exitCode = 1; });
