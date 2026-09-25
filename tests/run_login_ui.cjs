"use strict";

// Run only against a NEW tests/run_web_preview.py instance, never a real server.
// NODE_PATH=<runtime>/node_modules node tests/run_login_ui.cjs http://127.0.0.1:8802/
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {chromium, webkit} = require("playwright");

const base = new URL(process.argv[2] || "http://127.0.0.1:8802/");
if (base.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(base.hostname)
    || base.username || base.password || base.pathname !== "/" || base.search || base.hash
    || !base.port || Number(base.port) < 1024 || Number(base.port) > 65535) {
  throw new Error("Only an isolated loopback preview with an explicit unprivileged port and no query/hash is allowed.");
}
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "server-kit-login-ui-"));
const report = {directory, cases: [], failures: [], screenshots: [], jsErrors: [], blocked: []};
const password = "Preview-only-2026!";
const sessionCookie = `server_kit_preview_${base.port}`;
const csrfCookie = `server_kit_preview_csrf_${base.port}`;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const localUrl = value => {
  const url = new URL(value, base);
  assert.equal(url.origin, base.origin, "Test requests must remain on the isolated preview origin");
  return url.href;
};

async function screenshot(page, name) {
  await page.screenshot({path: path.join(directory, name + ".png"), animations: "disabled"});
  report.screenshots.push(name + ".png");
}

async function makeContext(browser, record, options = {}) {
  const context = await browser.newContext({viewport: {width: 390, height: 844}, ...options});
  await context.route("**/*", route => {
    const request = route.request();
    if (new URL(request.url()).origin === base.origin) return route.continue();
    report.blocked.push({case: record.name, origin: new URL(request.url()).origin});
    return route.abort();
  });
  context.on("page", page => {
    page.setDefaultTimeout(10000);
    page.on("pageerror", error => report.jsErrors.push({case: record.name, message: error.message}));
    page.on("response", response => {
      if (!response.request().isNavigationRequest()) return;
      const url = new URL(response.url());
      record.chain.push({method: response.request().method(), path: url.pathname,
        status: response.status(), location: response.headers().location || ""});
    });
  });
  return context;
}

async function fill(page, username = "preview") {
  await page.locator('[name="username"]').fill(username);
  await page.locator('[name="password"]').fill(password);
}

async function submit(page, mode = "single") {
  const navigation = page.waitForNavigation({waitUntil: "load", timeout: 20000});
  const button = page.locator('form button[type="submit"]');
  if (mode === "double-click") await button.dblclick({noWaitAfter: true});
  else if (mode === "enter-click") {
    await page.locator('[name="password"]').focus();
    await Promise.allSettled([page.keyboard.press("Enter"), button.click({noWaitAfter: true, timeout: 2500})]);
  } else await button.click({noWaitAfter: true});
  return navigation;
}

async function authenticatedGet(context, target = "/network/nodes/") {
  const response = await context.request.get(localUrl(target), {maxRedirects: 0});
  assert.equal(response.status(), 200, "The existing authenticated session must still work");
}

async function runCase(browser, engine, label, action, options = {}) {
  const record = {name: `${engine}-${label}`, chain: []};
  const context = await makeContext(browser, record, options);
  try {
    await action(context, record);
    record.passed = true;
  } catch (error) {
    record.passed = false;
    record.error = error.message;
    report.failures.push(record.name);
    const page = context.pages().at(-1);
    if (page && !page.isClosed()) await screenshot(page, `${record.name}-failure`).catch(() => {});
  } finally {
    report.cases.push(record);
    await context.close();
  }
}

async function verifySyntheticPreview(browser, engine) {
  const record = {name: `${engine}-preview-safety-check`, chain: []};
  const context = await makeContext(browser, record);
  try {
    const page = await context.newPage();
    await page.goto(localUrl("/__preview__/"));
    await fill(page);
    await submit(page);
    assert.equal(page.url(), localUrl("/__preview__/"));
    assert.match(await page.title(), /Local visual preview/);
    assert.match(await page.locator("h1").innerText(), /本地视觉审查.*合成数据/);
    assert.match(await page.locator("body").innerText(), /仅本机临时环境/);
  } finally {
    await context.close();
  }
}

async function normalLogin(context, record, route, expected, mode = "single") {
  const page = await context.newPage();
  await page.goto(localUrl(route));
  await fill(page);
  const response = await submit(page, mode);
  assert.equal(response.status(), 200);
  assert.equal(page.url(), localUrl(expected));
  const posts = record.chain.filter(item => item.method === "POST");
  assert.equal(posts.length, 1, "A click, double-click, or Enter+click must send only one login POST");
  assert.equal(posts[0].status, 302);
  await authenticatedGet(context);
  record.sessionCreated = (await context.cookies()).some(cookie => cookie.name === sessionCookie && Boolean(cookie.value));
  assert.equal(record.sessionCreated, true);
}

async function staleTabs(context, record, next = "/network/nodes/?from=stale", expected = "/network/nodes/?from=stale") {
  const route = `/login/?next=${encodeURIComponent(next)}`;
  const first = await context.newPage(), stale = await context.newPage();
  for (const page of [first, stale]) {await page.goto(localUrl(route)); await fill(page);}
  const before = await context.cookies();
  await submit(first);
  assert.equal(first.url(), localUrl(expected));
  const after = await context.cookies();
  record.sessionCreated = after.some(cookie => cookie.name === sessionCookie && Boolean(cookie.value));
  record.csrfRotated = before.find(cookie => cookie.name === csrfCookie)?.value !== after.find(cookie => cookie.name === csrfCookie)?.value;
  assert.equal(record.sessionCreated, true);
  assert.equal(record.csrfRotated, true);
  // A stale form is discarded, not re-authenticated or replayed with its password.
  await stale.locator('[name="password"]').fill("discard-this-stale-password");
  await delay(500);
  const response = await submit(stale);
  assert.equal(response.status(), 200);
  assert.equal(stale.url(), localUrl(expected));
  const posts = record.chain.filter(item => item.method === "POST");
  assert.deepEqual(posts.map(item => item.status), [302, 303]);
  assert.equal(record.chain.at(-1).method, "GET");
  assert.equal(record.chain.at(-1).status, 200);
  record.sameSessionPreserved = after.find(cookie => cookie.name === sessionCookie)?.value
    === (await context.cookies()).find(cookie => cookie.name === sessionCookie)?.value;
  assert.equal(record.sameSessionPreserved, true);
  await authenticatedGet(context);
  await screenshot(stale, `${record.name}-recovered`);
}

async function backToOldForm(context, record) {
  const page = await context.newPage();
  const route = "/login/?next=%2Fnetwork%2Fnodes%2F";
  await page.goto(localUrl(route));
  const oldHtml = await page.content(); // Kept in memory only; never writes CSRF tokens to artifacts.
  await fill(page);
  await submit(page);
  assert.equal(page.url(), localUrl("/network/nodes/"));
  let cachedResponse = false;
  // Deterministic browser-history cache boundary: return the original login DOM,
  // just as a back/forward cache or stale cached tab can retain an old token.
  await page.route(localUrl(route), route => {
    if (!cachedResponse && route.request().method() === "GET") {
      cachedResponse = true;
      return route.fulfill({status: 200, contentType: "text/html; charset=utf-8", body: oldHtml});
    }
    return route.continue();
  });
  await page.goBack({waitUntil: "load"});
  await page.locator('[name="username"]').waitFor();
  await fill(page);
  const response = await submit(page);
  assert.equal(response.status(), 200);
  assert.equal(page.url(), localUrl("/network/nodes/"));
  assert.deepEqual(record.chain.filter(item => item.method === "POST").map(item => item.status), [302, 303]);
  await authenticatedGet(context);
  await screenshot(page, `${record.name}-recovered`);
}

async function anonymousExpiredToken(context, record) {
  const page = await context.newPage();
  await page.goto(localUrl("/login/"));
  await fill(page);
  const cookie = (await context.cookies()).find(item => item.name === csrfCookie);
  assert.ok(cookie, "Preview must issue a CSRF cookie");
  await context.addCookies([{...cookie, value: "Z".repeat(32)}]);
  const response = await submit(page);
  assert.equal(response.status(), 403, "Anonymous stale login must never bypass CSRF validation");
  record.sessionCreated = (await context.cookies()).some(item => item.name === sessionCookie && Boolean(item.value));
  assert.equal(record.sessionCreated, false);
  assert.equal(record.chain.filter(item => item.method === "POST").length, 1);
  assert.match(await page.locator("body").innerText(), /CSRF/);
  await screenshot(page, `${record.name}-protected`);
  const denied = await context.request.get(localUrl("/network/nodes/"), {maxRedirects: 0});
  assert.equal(denied.status(), 302);
  assert.match(denied.headers().location, /^\/login\//);
  await page.goto(localUrl("/login/"));
  assert.equal(await page.locator('[name="password"]').inputValue(), "", "The password must not be automatically replayed");
  await fill(page);
  assert.equal((await submit(page)).status(), 200);
  assert.equal(page.url(), base.href);
}

async function restrictedStalePost(context, record, restriction) {
  const page = await context.newPage();
  await page.goto(localUrl("/login/"));
  const oldToken = await page.locator('[name="csrfmiddlewaretoken"]').inputValue();
  await fill(page); await submit(page);
  const before = (await context.cookies()).find(cookie => cookie.name === sessionCookie)?.value;
  const target = restriction === "non-login" ? "/logout/" : "/login/";
  const response = await context.request.post(localUrl(target), {maxRedirects: 0,
    headers: {Origin: restriction === "cross-origin" ? "https://untrusted.example.invalid" : base.origin,
      Referer: localUrl("/login/")},
    form: {username: restriction === "different-account" ? "viewer" : "preview",
      password: "discard-this-stale-password", csrfmiddlewaretoken: oldToken}});
  assert.equal(response.status(), 403, `${restriction} must retain Django's CSRF rejection`);
  record.protectedStatus = response.status();
  record.sameSessionPreserved = before === (await context.cookies()).find(cookie => cookie.name === sessionCookie)?.value;
  assert.equal(record.sameSessionPreserved, true);
  await authenticatedGet(context);
}

async function runEngine(engineName, engine) {
  const browser = await engine.launch({headless: true});
  try {
    await verifySyntheticPreview(browser, engineName);
    for (let repeat = 0; repeat < 2; repeat++) {
      for (const [route, expected, label] of [["/login/", "/", "login"], ["/", "/", "root"],
        ["/network/nodes/?from=login", "/network/nodes/?from=login", "node-deep-link"], ["/files/", "/files/", "file-deep-link"]]) {
        await runCase(browser, engineName, `${label}-${repeat}`, (context, record) => normalLogin(context, record, route, expected));
      }
      for (const mode of ["double-click", "enter-click"]) {
        await runCase(browser, engineName, `${mode}-${repeat}`, (context, record) => normalLogin(context, record, "/login/", "/", mode));
      }
    }
    await runCase(browser, engineName, "no-js", (context, record) => normalLogin(context, record, "/network/nodes/", "/network/nodes/"), {javaScriptEnabled: false});
    await runCase(browser, engineName, "stale-second-tab", staleTabs);
    await runCase(browser, engineName, "back-to-cached-form", backToOldForm);
    await runCase(browser, engineName, "anonymous-expired-token", anonymousExpiredToken);
    for (const restriction of ["cross-origin", "different-account", "non-login"]) {
      await runCase(browser, engineName, restriction, (context, record) => restrictedStalePost(context, record, restriction));
    }
    for (const [next, label] of [["https://untrusted.example.invalid/", "external"], ["//untrusted.example.invalid/", "protocol-relative"],
      ["/login/", "login-loop"], ["/logout/", "logout"], ["/%6cogin/", "encoded-login-loop"],
      ["#section", "fragment-login-loop"], ["?next=%23section", "query-login-loop"], ["/network/../login/", "dot-segment-login-loop"]]) {
      await runCase(browser, engineName, `unsafe-next-${label}`,
        (context, record) => normalLogin(context, record, `/login/?next=${encodeURIComponent(next)}`, "/"));
    }
    await runCase(browser, engineName, "stale-unsafe-next", (context, record) => staleTabs(context, record, "https://untrusted.example.invalid/", "/"));
  } finally {
    await browser.close();
  }
}

(async () => {
  const engines = await Promise.allSettled([runEngine("chromium", chromium), runEngine("webkit", webkit)]);
  for (const [index, result] of engines.entries()) {
    if (result.status === "rejected") report.failures.push(`${["chromium", "webkit"][index]}: ${result.reason.message}`);
  }
  fs.writeFileSync(path.join(directory, "report.json"), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({directory, cases: report.cases.length, passed: report.cases.filter(item => item.passed).length,
    failures: report.failures, screenshots: report.screenshots.length, jsErrors: report.jsErrors, blocked: report.blocked}, null, 2));
  if (report.failures.length || report.jsErrors.length || report.blocked.length) process.exitCode = 1;
})().catch(error => {console.error(error.message); process.exitCode = 1;});
