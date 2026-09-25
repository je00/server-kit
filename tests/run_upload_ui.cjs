"use strict";

// Real browser DOM + mocked XHR only. Every URL is intercepted, and no upload
// or other request reaches the local network, a preview server, or a VPS.
// NODE_PATH=<runtime node_modules> node tests/run_upload_ui.cjs
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {chromium, webkit} = require("playwright");

const base = "http://127.0.0.1:18776";
const scripts = new Map(["uploads.js", "app.js"].map(name => [
  `/${name}`, fs.readFileSync(path.join(__dirname, "../web/static", name), "utf8"),
]));
const html = `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<script src="/uploads.js" defer></script><script src="/app.js" defer></script></head><body>
<main id="main-content"><form method="post" enctype="multipart/form-data" action="/files/add/"
 data-upload-form data-max-upload-bytes="1024" data-upload-return-url="/files/">
<input name="csrfmiddlewaretoken" type="hidden" value="fixture-csrf">
<input type="file" name="payload" required><input name="download_name" value="demo.zip">
<select name="cache_ttl"><option value="86400" selected>One day</option></select>
<input name="password" type="password" required value="fixture-password">
<input name="confirmed" type="hidden" value="yes"><input name="already_disabled" disabled value="omit">
<button type="submit">上传并发布</button>
<section data-upload-progress hidden><progress data-upload-meter max="100" value="0"></progress>
<p data-upload-status role="status" tabindex="-1"></p><p data-upload-error role="alert" hidden></p>
<div data-upload-recovery hidden><a href="/audit/" target="_blank">检查任务记录</a>
<button type="button" data-upload-acknowledge>已检查，允许重新提交</button></div></section>
</form></main><div data-interaction-feedback hidden></div></body></html>`;

async function fixture(browser, width) {
  const context = await browser.newContext({viewport: {width, height: 844}});
  const blocked = [];
  await context.route("**/*", route => {
    const url = new URL(route.request().url());
    if (url.origin !== base) { blocked.push(url.href); return route.abort(); }
    if (scripts.has(url.pathname)) return route.fulfill({contentType: "text/javascript", body: scripts.get(url.pathname)});
    if (url.pathname === "/files/") return route.fulfill({contentType: "text/html", body: html});
    if (/^\/tasks\/task-[0-9a-f]{32}\/$/.test(url.pathname)) {
      return route.fulfill({contentType: "text/html", body: "<!doctype html><h1>Fixture task</h1>"});
    }
    blocked.push(url.href);
    return route.abort();
  });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.addInitScript(() => {
    window.uploadRequests = [];
    class FakeXHR extends EventTarget {
      constructor() {
        super(); this.upload = new EventTarget(); this.headers = {};
        this.status = 0; this.responseText = ""; this.responseURL = "";
      }
      open(method, url, async) { this.method = method; this.url = url; this.async = async; }
      setRequestHeader(name, value) { this.headers[name] = value; }
      getResponseHeader() { return "text/html; charset=utf-8"; }
      send(body) { this.body = body; window.uploadRequests.push(this); }
      progress(loaded, total) {
        this.upload.dispatchEvent(new ProgressEvent("progress", {lengthComputable: total > 0, loaded, total}));
      }
      finish({status = 200, url = `${location.origin}/files/`, body = "", type = "load"} = {}) {
        this.status = status; this.responseURL = url; this.responseText = body;
        this.dispatchEvent(new Event(type));
      }
    }
    window.XMLHttpRequest = FakeXHR;
  });
  await page.clock.install();
  await page.goto(`${base}/files/`);
  await page.locator('[name="payload"]').setInputFiles({name: "fixture.zip", mimeType: "application/zip", buffer: Buffer.from("FAKE FILE ONLY")});
  const start = () => page.locator('button[type="submit"]').click();
  const postAgain = () => page.evaluate(() => document.querySelector("form").requestSubmit());
  const count = () => page.evaluate(() => window.uploadRequests.length);
  const finish = values => page.evaluate(values => window.uploadRequests.at(-1).finish(values), values);
  const close = async () => {
    assert.deepEqual(errors, []);
    assert.deepEqual(blocked, []);
    await context.close();
  };
  return {context, page, start, postAgain, count, finish, close};
}

async function suite(browserType, width) {
  const browser = await browserType.launch({headless: true});
  let passed = 0;
  try {
    {
      const f = await fixture(browser, width);
      await f.start();
      const payload = await f.page.evaluate(() => {
        const request = window.uploadRequests[0];
        return {method: request.method, credentials: request.withCredentials, timeout: request.timeout,
          csrf: request.body.get("csrfmiddlewaretoken"), password: request.body.get("password"),
          name: request.body.get("payload").name, disabled: request.body.has("already_disabled")};
      });
      assert.deepEqual(payload, {method: "POST", credentials: true, timeout: 0, csrf: "fixture-csrf",
        password: "fixture-password", name: "fixture.zip", disabled: false});
      await f.page.clock.fastForward(16001);
      await f.postAgain();
      assert.equal(await f.count(), 1, "slow upload cannot trigger a second POST after the global 15 second guard");
      assert.equal(await f.page.locator('button[type="submit"]').isDisabled(), true);
      assert.equal(await f.page.evaluate(() => {
        const event = new Event("beforeunload", {cancelable: true});
        window.dispatchEvent(event); return event.defaultPrevented;
      }), true);
      await f.page.evaluate(() => window.uploadRequests[0].progress(100, 100));
      assert.equal(await f.page.locator("[data-upload-meter]").evaluate(element => element.value), 100);
      assert.match(await f.page.locator("[data-upload-status]").textContent(), /尚未发布完成/);
      assert.equal(await f.page.locator('button[type="submit"]').isDisabled(), true);
      await f.close(); passed++;
    }
    {
      const f = await fixture(browser, width);
      await f.start();
      await f.finish({body: '<main id="main-content"><div class="alert danger" role="alert">密码错误，请重试。</div><script>window.untrustedScriptRan=true</script></main>'});
      assert.match(await f.page.locator("[data-upload-error]").textContent(), /密码错误/);
      assert.equal(await f.page.locator('button[type="submit"]').isDisabled(), false);
      assert.equal(await f.page.locator('[name="already_disabled"]').isDisabled(), true);
      assert.equal(await f.page.locator('[name="download_name"]').inputValue(), "demo.zip");
      assert.equal(await f.page.evaluate(() => document.querySelector('[name="payload"]').files[0].name), "fixture.zip");
      assert.equal(await f.page.evaluate(() => Boolean(window.untrustedScriptRan)), false);
      assert.equal(await f.page.evaluate(() => {
        const event = new Event("beforeunload", {cancelable: true});
        window.dispatchEvent(event); return event.defaultPrevented;
      }), false);
      await f.start(); assert.equal(await f.count(), 2);
      await f.close(); passed++;
    }
    for (const type of ["error", "timeout", "abort"]) {
      const f = await fixture(browser, width);
      await f.start(); await f.finish({type});
      assert.equal(await f.page.locator('[data-upload-recovery]').isVisible(), true);
      assert.equal(await f.page.locator('button[type="submit"]').isDisabled(), true);
      await f.page.clock.fastForward(60000); await f.postAgain();
      assert.equal(await f.count(), 1, "uncertain outcomes are not automatically retried");
      await f.page.locator("[data-upload-acknowledge]").click();
      assert.equal(await f.page.locator('button[type="submit"]').isDisabled(), false);
      await f.start(); assert.equal(await f.count(), 2);
      await f.close(); passed++;
    }
    for (const url of ["https://example.invalid/tasks/task-" + "a".repeat(32) + "/",
      `${base}/tasks/task-${"a".repeat(32)}/extra/`, `${base}/files/?next=/tasks/task-${"a".repeat(32)}/`]) {
      const f = await fixture(browser, width);
      await f.start(); await f.finish({url});
      assert.equal(f.page.url(), `${base}/files/`);
      assert.equal(await f.page.locator('[data-upload-recovery]').isVisible(), true);
      assert.equal(await f.page.locator('button[type="submit"]').isDisabled(), true);
      await f.close(); passed++;
    }
    {
      const f = await fixture(browser, width);
      await f.start(); await f.finish({url: `${base}/login/?next=/files/add/`});
      assert.match(await f.page.locator("[data-upload-error]").textContent(), /登录/);
      assert.equal(await f.page.locator('button[type="submit"]').isDisabled(), false);
      assert.equal(f.page.url(), `${base}/files/`);
      await f.close(); passed++;
    }
    {
      const f = await fixture(browser, width);
      await f.page.locator('[name="payload"]').setInputFiles({name: "too-large.zip", mimeType: "application/zip", buffer: Buffer.alloc(2048)});
      await f.start(); assert.equal(await f.count(), 0);
      assert.match(await f.page.locator("[data-upload-error]").textContent(), /超过/);
      assert.equal(await f.page.locator('button[type="submit"]').isDisabled(), false);
      await f.close(); passed++;
    }
    {
      const f = await fixture(browser, width);
      await f.start();
      const pathname = `/tasks/task-${"a".repeat(32)}/`;
      await Promise.all([f.page.waitForURL(`${base}${pathname}`), f.finish({url: `${base}${pathname}?ignored=1#ignored`})]);
      assert.equal(f.page.url(), `${base}${pathname}`);
      await f.close(); passed++;
    }
    console.log(`${browserType.name()} ${width}px: ${passed} upload interaction contracts passed; no network requests`);
  } finally { await browser.close(); }
}

(async () => {
  await suite(chromium, 1440);
  await suite(webkit, 390);
})().catch(error => { console.error(error); process.exitCode = 1; });
