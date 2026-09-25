"use strict";

// Real-browser integration checks for the isolated synthetic preview only.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {chromium, webkit} = require("playwright");
const base = new URL(process.argv[2] || "http://127.0.0.1:8765/");
if (base.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(base.hostname)
    || base.username || base.password || base.pathname !== "/") throw new Error("Only an isolated loopback preview is allowed.");
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "server-kit-inline-tasks-"));
const report = {directory, checks: [], screenshots: [], errors: [], blocked: []};
const password = "Preview-only-2026!";
const yaml = "type: socks5\nserver: synthetic-proxy.example\nport: 1080\nusername: synthetic-user\npassword: synthetic-secret\nudp: true\n";
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function session(browser, route, width) {
  const context = await browser.newContext({viewport: {width, height: width < 768 ? 844 : 1000},
    ...(width < 768 ? {isMobile: true, hasTouch: true} : {})});
  await context.route("**/*", route => {
    if (new URL(route.request().url()).origin === base.origin) return route.continue();
    report.blocked.push(route.request().url());
    return route.abort();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(7000);
  page.on("pageerror", error => report.errors.push(error.message));
  page.on("dialog", dialog => dialog.accept());
  await page.goto(new URL("login/", base).href);
  await page.locator('[name="username"]').fill("preview");
  await page.locator('[name="password"]').fill(password);
  await Promise.all([page.waitForURL(base.href), page.locator('button[type="submit"]').click()]);
  assert.equal((await context.request.get(new URL("__preview__/scenario/rich/", base).href)).status(), 200);
  await page.goto(new URL(route, base).href);
  const navigations = [], requests = [];
  page.on("framenavigated", frame => { if (frame === page.mainFrame()) navigations.push(frame.url()); });
  page.on("request", request => requests.push({url: request.url(), method: request.method()}));
  return {context, page, navigations, requests};
}

async function expand(locator) {
  await locator.evaluate(node => {
    for (let ancestor = node; ancestor; ancestor = ancestor.parentElement) {
      if (ancestor.tagName === "DETAILS") ancestor.open = true;
    }
  });
}
const modal = page => page.locator("[data-inline-task-modal]");
const formFor = (page, action, field, value) => page.locator(`form[action="${action}"]:has(input[name="${field}"][value="${value}"])`);
const proxyForm = (page, operation, id = "") => page.locator(`form:has(input[name="operation"][value="${operation}"])${id ? `:has(input[value="${id}"])` : ""}`);

async function preview(page, form) {
  await expand(form);
  await form.locator('button[type="submit"]').click();
  await modal(page).locator("[data-inline-confirm]").waitFor({state: "visible"});
  assert.equal(await modal(page).getAttribute("hidden"), null);
}

async function complete(page, duplicate = false) {
  const dialog = modal(page);
  if (duplicate) await dialog.locator("[data-inline-confirm]").evaluate(button => { button.click(); button.click(); });
  else await dialog.locator("[data-inline-confirm]").click();
  await dialog.locator("[data-inline-done]").waitFor({state: "visible"});
  assert.match(await dialog.locator("[data-inline-status]").innerText(), /已保存/);
  await dialog.locator("[data-inline-done]").click();
  await dialog.waitFor({state: "hidden"});
}

async function screenshot(page, label) {
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true, `${label}: page overflow`);
  const dialog = page.locator('[role="dialog"]:visible');
  if (await dialog.count()) {
    assert.equal(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth + 1), true, `${label}: dialog overflow`);
  }
  await page.screenshot({path: path.join(directory, label + ".png")});
  report.screenshots.push(label + ".png");
}

async function proxyDrafts(browser, label, width) {
  const {context, page, navigations, requests} = await session(browser, "network/proxy/", width);
  try {
    const exit = proxyForm(page, "exit_update", "333333333333");
    await expand(exit);
    await exit.locator('[name="exit_proxy_yaml"]').fill(yaml);
    await exit.locator('[name="password"]').fill("wrong-demo-password");
    await exit.locator('[name="confirmed"]').check();
    await exit.locator('button[type="submit"]').click();
    await modal(page).locator("[data-inline-error]").waitFor({state: "visible"});
    assert.match(await modal(page).locator("[data-inline-error]").innerText(), /密码/);
    await screenshot(page, `${label}-${width}-proxy-password-error`);
    await modal(page).locator("[data-inline-edit]").click();
    assert.equal(await exit.locator('[name="exit_proxy_yaml"]').inputValue(), yaml);
    assert.equal(await exit.locator('[name="password"]').isEnabled(), true);
    await exit.locator('[name="password"]').fill(password);
    await preview(page, exit);
    assert.doesNotMatch(await modal(page).innerText(), /synthetic-secret/);
    await page.keyboard.press("Escape");
    assert.equal(await exit.locator('[name="exit_proxy_yaml"]').inputValue(), yaml);
    assert.equal(await exit.locator('[name="confirmed"]').isChecked(), true);
    const airport = proxyForm(page, "airport_update", "111111111111");
    await expand(airport);
    await airport.locator('[name="airport_name"]').fill("reviewed-airport");
    await airport.locator('[name="countries"][value="fr"]').check();
    await airport.locator('[name="password"]').fill(password);
    await airport.locator('[name="confirmed"]').check();
    await preview(page, airport);
    await screenshot(page, `${label}-${width}-proxy-review`);
    await complete(page, true);
    const fresh = proxyForm(page, "airport_update", "111111111111");
    assert.equal(await fresh.locator('[name="airport_name"]').inputValue(), "reviewed-airport");
    assert.equal(await fresh.locator('[name="countries"][value="fr"]').isChecked(), true);
    assert.equal(await exit.locator('[name="exit_proxy_yaml"]').inputValue(), yaml, "other proxy YAML must not be overwritten");
    assert.equal(await exit.locator('[name="password"]').inputValue(), password);
    assert.equal(requests.filter(item => item.url.endsWith("/inline-tasks/execute/")).length, 1);
    // Replaced content must get its country-picker and filter behavior back.
    await fresh.locator('[name="countries"][value="all"]').check();
    assert.equal(await fresh.locator('[name="countries"]:checked').count(), 1);
    await page.locator('#airport-resources [data-filter-input]').fill("reviewed-airport");
    assert.equal(await page.locator('#airport-resources [data-filter-item]:visible').count(), 1);
    await page.locator('#airport-resources [data-filter-input]').fill("");
    const creation = proxyForm(page, "airport_add");
    await expand(creation);
    await creation.locator('[name="airport_name"]').fill("added-synthetic-airport");
    await creation.locator('[name="airport_url"]').fill("https://subscription.example/preview-only");
    await creation.locator('[name="password"]').fill(password);
    await creation.locator('[name="confirmed"]').check();
    await preview(page, creation);
    await complete(page);
    assert.equal(await creation.locator('[name="airport_name"]').inputValue(), "");
    assert.equal(await creation.locator('[name="airport_url"]').inputValue(), "");
    assert.equal(await page.locator('#airport-resources [data-filter-item]').count(), 4);
    assert.match(await page.locator('#airport-resources .section-heading .eyebrow').innerText(), /4/);
    assert.match(await page.locator('.page-header .stage-badge').innerText(), /3\s*\/\s*4/);
    const added = page.locator('#airport-resources .airport-card').filter({has: page.locator('[name="airport_name"][value="added-synthetic-airport"]')});
    const remove = added.locator('form:has([name="operation"][value="airport_delete"])');
    await expand(remove);
    await remove.locator('[name="password"]').fill(password);
    await remove.locator('[name="confirmed"]').check();
    await preview(page, remove);
    await complete(page);
    assert.equal(await page.locator('#airport-resources [data-filter-item]').count(), 3);
    assert.match(await page.locator('#airport-resources .section-heading .eyebrow').innerText(), /3/);
    assert.match(await page.locator('.page-header .stage-badge').innerText(), /2\s*\/\s*3/);
    assert.equal(await exit.locator('[name="exit_proxy_yaml"]').inputValue(), yaml);
    const createExit = proxyForm(page, "exit_add");
    await expand(createExit);
    await createExit.locator('[name="exit_name"]').fill("preview-added-exit");
    await createExit.locator('[name="exit_input_mode"][value="yaml"]').check();
    await createExit.locator('[name="exit_proxy_yaml"]').fill(yaml);
    await createExit.locator('[name="password"]').fill(password);
    await createExit.locator('[name="confirmed"]').check();
    await preview(page, createExit);
    await complete(page);
    assert.equal(await createExit.locator('[name="exit_input_mode"][value="fields"]').isChecked(), true);
    assert.equal(await createExit.locator('[data-exit-input-panel="fields"]').isVisible(), true, "reset the visible editor to the default field mode");
    assert.equal(await createExit.locator('[data-exit-input-panel="yaml"]').isHidden(), true);
    assert.equal(await createExit.locator('[name="exit_field_server"]').isEnabled(), true, "new field editor must remain usable after a YAML submission");
    assert.equal(await createExit.locator('[name="exit_proxy_yaml"]').inputValue(), "");
    assert.equal(await createExit.locator('[name="password"]').inputValue(), "");
    assert.equal(await page.locator('#exit-resources [data-filter-item]').count(), 3);
    assert.match(await page.locator('#exit-resources .section-heading .eyebrow').innerText(), /3/);
    assert.deepEqual(navigations, []);
    report.checks.push(`${label} ${width}: proxy password failure/cancel preserve YAML; double-confirm saves once; resource create/delete update all counts; unrelated draft, filters and country controls preserved`);
  } finally { await context.close(); }
}

async function domainDrafts(browser, label, width) {
  const {context, page, navigations} = await session(browser, "network/subscriptions/", width);
  try {
    const action = "/network/nodes/domains/preview/";
    const other = formFor(page, action, "name", "home-desktop");
    await other.locator('[name="domains"]').fill("unsaved-desktop.internal.example");
    const current = formFor(page, action, "name", "nas-storage-primary");
    await current.locator('[name="domains"]').fill("saved-nas.internal.example, *.saved-nas.internal.example");
    await preview(page, current);
    await modal(page).locator("[data-inline-edit]").click();
    assert.match(await current.locator('[name="domains"]').inputValue(), /saved-nas/);
    await preview(page, current);
    await complete(page);
    assert.equal(await other.locator('[name="domains"]').inputValue(), "unsaved-desktop.internal.example");
    assert.match(await formFor(page, action, "name", "nas-storage-primary").locator('[name="domains"]').inputValue(), /saved-nas/);
    const create = page.locator(".custom-host-create-form");
    await create.locator('[name="address"]').fill("192.0.2.44");
    await create.locator('[name="domains"]').fill("new-host.internal.example");
    await preview(page, create);
    await complete(page);
    assert.equal(await page.locator('.custom-host-records article:has(input[value="192.0.2.44"])').count(), 1);
    assert.equal(await create.locator('[name="address"]').inputValue(), "");
    assert.equal(await other.locator('[name="domains"]').inputValue(), "unsaved-desktop.internal.example");
    await screenshot(page, `${label}-${width}-domains-saved`);
    assert.deepEqual(navigations, []);
    report.checks.push(`${label} ${width}: same-page DNS edit/cancel/create refresh without losing another row's draft`);
  } finally { await context.close(); }
}

async function nodeDrafts(browser, label, width) {
  const {context, page, navigations, requests} = await session(browser, "network/nodes/", width);
  try {
    const batch = page.locator('[data-permission-batch]:has(input[name="client"][value="iphone-travel"])');
    await expand(batch);
    await batch.locator('[name="target"]').selectOption("vps");
    await batch.locator('[name="ports"]').fill("8443");
    const card = batch.locator('xpath=ancestor::details[contains(@class,"node-permission-card")]');
    for (let remaining = 1; remaining >= 0; remaining--) {
      const deletion = card.locator('[data-permission-list] form').first();
      await preview(page, deletion);
      await complete(page);
      assert.equal(await batch.locator('[name="ports"]').inputValue(), "8443");
      assert.equal(await card.locator('[data-permission-list]').count(), 1, "keep the empty list container after deleting the last rule");
      assert.equal(await card.locator('[data-permission-list] .permission-row').count(), remaining);
    }
    await batch.locator('[data-permission-preview]').click();
    await batch.locator('[data-permission-confirm]').waitFor({state: "visible"});
    await batch.locator('[data-permission-confirm]').click();
    await batch.locator('[data-permission-continue]').waitFor({state: "visible"});
    assert.match(await batch.locator('[data-permission-status]').innerText(), /列表已更新/);
    assert.equal(await card.locator('[data-permission-list] .permission-row').count(), 1);
    const exits = formFor(page, "/network/nodes/exits/preview/", "name", "iphone-travel");
    await expand(exits);
    await exits.locator('[name="exit_ids"][value="333333333333"]').uncheck();
    await exits.locator('[name="exit_ids"][value="444444444444"]').check();
    await preview(page, exits);
    await complete(page);
    const fresh = formFor(page, "/network/nodes/exits/preview/", "name", "iphone-travel");
    assert.equal(await fresh.locator('[name="exit_ids"][value="444444444444"]').isChecked(), true);
    assert.equal(await fresh.locator('[name="exit_ids"][value="333333333333"]').isChecked(), false);
    assert.equal(await fresh.locator('xpath=ancestor::details[contains(@class,"node-exit-card")]').getAttribute("open"), "", "keep saved exit editor open");
    assert.equal(requests.filter(item => item.url.endsWith("/inline-tasks/execute/")).length, 3);
    await screenshot(page, `${label}-${width}-node-exits-saved`);
    assert.deepEqual(navigations, []);
    report.checks.push(`${label} ${width}: inline permission deletion preserves batch drafts, last-rule deletion allows adding again, exit selection stays open and same-page`);
  } finally { await context.close(); }
}

async function lostConfirmation(browser, label) {
  const {context, page, requests, navigations} = await session(browser, "network/subscriptions/", 390);
  try {
    const form = formFor(page, "/network/nodes/domains/preview/", "name", "nas-storage-primary");
    await form.locator('[name="domains"]').fill("lost-response.internal.example");
    await preview(page, form);
    await page.route("**/inline-tasks/execute/", async route => {
      assert.equal((await route.fetch()).status(), 200);
      await route.abort("connectionclosed");
    });
    await modal(page).locator("[data-inline-confirm]").click();
    await modal(page).locator("[data-inline-retry]").waitFor({state: "visible"});
    assert.match(await modal(page).locator("[data-inline-status]").innerText(), /不会自动重复提交/);
    await screenshot(page, `${label}-390-confirm-response-lost`);
    await delay(2700);
    assert.equal(requests.filter(item => item.url.endsWith("/inline-tasks/execute/")).length, 1);
    assert.equal(requests.filter(item => item.method === "GET" && /\/inline-tasks\/task-/.test(item.url)).length, 0);
    await modal(page).locator("[data-inline-retry]").click();
    await modal(page).locator("[data-inline-done]").waitFor({state: "visible"});
    await modal(page).locator("[data-inline-done]").click();
    assert.equal(await formFor(page, "/network/nodes/domains/preview/", "name", "nas-storage-primary").locator('[name="domains"]').inputValue(), "lost-response.internal.example");
    assert.equal(requests.filter(item => item.url.endsWith("/inline-tasks/execute/")).length, 1);
    assert.deepEqual(navigations, []);
    report.checks.push(`${label}: accepted but lost confirmation does not retry mutations; manual read-only status resumes refresh`);
  } finally { await context.close(); }
}

async function failedListRefresh(browser, label) {
  const {context, page, requests, navigations} = await session(browser, "network/subscriptions/", 390);
  try {
    const action = "/network/nodes/domains/preview/";
    const other = formFor(page, action, "name", "home-desktop");
    await other.locator('[name="domains"]').fill("keep-unsaved-refresh.internal.example");
    const originalCount = await page.locator(".global-host-records article").count();
    let snapshot = "";
    await page.route(new URL("network/subscriptions/", base).href, route => {
      if (route.request().method() !== "GET" || !snapshot) return route.continue();
      const body = snapshot === "error" ? '<div class="alert danger" role="alert">模拟状态读取失败</div>' : '<section class="empty-state">尚未配置</section>';
      return route.fulfill({status: 200, contentType: "text/html", body: `<!doctype html><html><main id="main-content" class="content">${body}</main></html>`});
    });
    for (const fault of ["error", "unconfigured"]) {
      const form = formFor(page, action, "name", "nas-storage-primary");
      const value = `saved-${fault}.internal.example`;
      await form.locator('[name="domains"]').fill(value);
      await preview(page, form);
      const before = requests.filter(item => item.url.endsWith("/inline-tasks/execute/")).length;
      snapshot = fault;
      await modal(page).locator("[data-inline-confirm]").click();
      await modal(page).locator("[data-inline-refresh]").waitFor({state: "visible"});
      assert.match(await modal(page).locator("[data-inline-status]").innerText(), /任务已成功/);
      assert.match(await modal(page).locator("[data-inline-error]").innerText(), /未覆盖/);
      assert.equal(await page.locator(".global-host-records article").count(), originalCount);
      assert.equal(await other.locator('[name="domains"]').inputValue(), "keep-unsaved-refresh.internal.example");
      assert.equal(await form.locator('[name="domains"]').inputValue(), value);
      assert.equal(await modal(page).locator("[data-inline-confirm]").isVisible(), false);
      assert.equal(await modal(page).locator("[data-inline-edit]").isVisible(), false);
      await screenshot(page, `${label}-390-${fault}-snapshot-preserved`);
      snapshot = "";
      await modal(page).locator("[data-inline-refresh]").click();
      await modal(page).locator("[data-inline-done]").waitFor({state: "visible"});
      await modal(page).locator("[data-inline-done]").click();
      assert.equal(await formFor(page, action, "name", "nas-storage-primary").locator('[name="domains"]').inputValue(), value);
      assert.equal(await other.locator('[name="domains"]').inputValue(), "keep-unsaved-refresh.internal.example");
      assert.equal(requests.filter(item => item.url.endsWith("/inline-tasks/execute/")).length, before + 1, "retrying the list must never re-confirm a task");
    }
    assert.deepEqual(navigations, []);
    report.checks.push(`${label}: error and unconfigured/incomplete HTML snapshots preserve existing rows and drafts; manual list refresh recovers without mutations`);
  } finally { await context.close(); }
}

async function expiredUnlock(browser, label, resource) {
  const proxy = resource === "proxy";
  const {context, page, navigations} = await session(browser, proxy ? "network/proxy/" : "files/", 390);
  try {
    if (proxy && !(await page.locator('[data-secret-action="view"]').count())) {
      const csrf = await page.locator('[name="csrfmiddlewaretoken"]').first().inputValue();
      const result = await context.request.post(new URL("sensitive/unlock/", base).href,
        {headers: {Accept: "application/json"}, form: {csrfmiddlewaretoken: csrf, password, destination: "proxy"}});
      assert.equal(result.status(), 200);
      await page.goto(new URL("network/proxy/", base).href);
      navigations.length = 0;
    }
    let draft;
    if (proxy) {
      draft = proxyForm(page, "exit_update", "333333333333");
      await expand(draft);
      await draft.locator('[name="exit_proxy_yaml"]').fill(yaml);
    } else {
      draft = page.locator("[data-upload-form]");
      await draft.locator('[name="payload"]').setInputFiles({name: "synthetic-draft.txt", mimeType: "text/plain", buffer: Buffer.from("preview-only")});
      await draft.locator('[name="download_name"]').fill("keep-upload-name.txt");
    }
    const button = page.locator(proxy ? '[data-secret-action="view"]' : '[data-secret-action="qr"]').first();
    const endpoint = await button.getAttribute("data-endpoint");
    let reads = 0;
    await page.route(new URL(endpoint, base).href, route => {
      reads++;
      return reads === 1 ? route.fulfill({status: 403, contentType: "application/json", body: JSON.stringify({code: "sensitive_unlock_required", error: "模拟短时解锁已过期"})}) : route.continue();
    });
    await button.click();
    const auth = page.locator("[data-sensitive-auth-modal]");
    await auth.waitFor({state: "visible"});
    await auth.locator('[name="password"]').fill("wrong-demo-password");
    await auth.locator('button[type="submit"]').click();
    await auth.locator('[data-sensitive-auth-error]').waitFor({state: "visible"});
    assert.match(await auth.locator('[data-sensitive-auth-error]').innerText(), /密码/);
    await auth.locator('[name="password"]').fill(password);
    await auth.locator('button[type="submit"]').click();
    await auth.waitFor({state: "hidden"});
    const result = page.locator(proxy ? '[data-secret-modal]' : '[data-qr-modal]');
    await result.waitFor({state: "visible"});
    assert.equal(reads, 2, "resume the original resource action once after unlock");
    assert.equal(await auth.locator('[name="password"]').inputValue(), "");
    if (proxy) assert.equal(await draft.locator('[name="exit_proxy_yaml"]').inputValue(), yaml);
    else {
      assert.equal(await draft.locator('[name="download_name"]').inputValue(), "keep-upload-name.txt");
      assert.equal(await draft.locator('[name="payload"]').evaluate(input => input.files[0].name), "synthetic-draft.txt");
    }
    await screenshot(page, `${label}-390-${resource}-unlock-resumed`);
    await result.locator(proxy ? '[data-secret-close].qr-close' : '[data-qr-close].qr-close').click();
    if (proxy) assert.equal(await result.locator('[data-secret-value]').innerText(), "");
    assert.deepEqual(navigations, []);
    report.checks.push(`${label}: ${resource} expired unlock and wrong password resume original action once without losing YAML/upload drafts or navigating`);
  } finally { await context.close(); }
}

(async () => {
  try {
    for (const [label, engine] of [["chromium", chromium], ["webkit", webkit]]) {
      const browser = await engine.launch({headless: true});
      try {
        for (const width of [1440, 390]) {
          await proxyDrafts(browser, label, width);
          await domainDrafts(browser, label, width);
          await nodeDrafts(browser, label, width);
        }
        await lostConfirmation(browser, label);
        await failedListRefresh(browser, label);
        await expiredUnlock(browser, label, "proxy");
        await expiredUnlock(browser, label, "files");
      } finally { await browser.close(); }
    }
    assert.deepEqual(report.errors, []);
    assert.deepEqual(report.blocked, []);
    console.log(JSON.stringify(report, null, 2));
  } catch (error) {
    report.failure = error.stack;
    console.error(error.stack);
    process.exitCode = 1;
  } finally {
    fs.writeFileSync(path.join(directory, "report.json"), JSON.stringify(report, null, 2));
    console.log(`Inline-task QA artifacts: ${directory}`);
  }
})();
