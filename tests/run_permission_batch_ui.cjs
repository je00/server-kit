"use strict";

// End-to-end QA against tests/run_web_preview.py only. Never targets a VPS.
// NODE_PATH=<runtime>/node_modules node tests/run_permission_batch_ui.cjs [http://127.0.0.1:8765/]
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {chromium, webkit} = require("playwright");

const base = new URL(process.argv[2] || "http://127.0.0.1:8765/");
if (base.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(base.hostname)
    || base.username || base.password || base.pathname !== "/") {
  throw new Error("Use only an isolated loopback preview origin.");
}
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "server-kit-permission-batch-"));
const report = {directory, checks: [], screenshots: [], errors: [], blocked: []};
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const batchPath = "/network/permissions/batch/";
const marker = '<img src=x onerror="window.__permissionXss=true">';

async function session(browser, width = 1440) {
  const context = await browser.newContext({viewport: {width, height: width < 768 ? 844 : 1000},
    ...(width < 768 ? {isMobile: true, hasTouch: true} : {})});
  await context.route("**/*", route => {
    if (new URL(route.request().url()).origin === base.origin) return route.continue();
    report.blocked.push(route.request().url());
    return route.abort();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(8000);
  page.on("pageerror", error => report.errors.push(error.message));
  page.on("dialog", dialog => dialog.accept());
  await page.goto(new URL("login/", base).href);
  await page.locator('[name="username"]').fill("preview");
  await page.locator('[name="password"]').fill("Preview-only-2026!");
  await Promise.all([page.waitForURL(base.href), page.locator('button[type="submit"]').click()]);
  const reset = await context.request.get(new URL("__preview__/scenario/rich/", base).href);
  assert.equal(reset.status(), 200);
  await page.goto(new URL("network/nodes/", base).href);
  const navigations = [];
  const requests = [];
  page.on("framenavigated", frame => { if (frame === page.mainFrame()) navigations.push(frame.url()); });
  page.on("request", request => {
    if (request.url().includes(batchPath)) requests.push({url: request.url(), method: request.method()});
  });
  return {context, page, navigations, requests};
}

async function editor(page, name = "iphone-travel") {
  const form = page.locator(`[data-permission-batch]:has(input[name="client"][value="${name}"])`);
  assert.equal(await form.count(), 1);
  await form.evaluate(node => {
    for (let parent = node.parentElement; parent; parent = parent.parentElement) {
      if (parent.tagName === "DETAILS") parent.open = true;
    }
  });
  return form;
}

async function rule(form, index, target, network, ports = "") {
  const row = form.locator("[data-permission-row]").nth(index);
  await row.locator('[name="target"]').selectOption(target);
  await row.locator('[name="port_mode"]').selectOption(network);
  if (network !== "all") await row.locator('[name="ports"]').fill(ports);
}

async function preview(form) {
  await form.locator("[data-permission-preview]").click();
  await form.locator("[data-permission-review]").waitFor({state: "visible"});
  assert.equal(await form.locator("[data-permission-rows]").isHidden(), true);
  assert.equal(await form.locator("[data-permission-draft-help]").isHidden(), true);
  assert.equal(await form.locator("[data-permission-review-title]").evaluate(node => document.activeElement === node), true);
}

async function success(form) {
  await form.locator("[data-permission-continue]").waitFor({state: "visible"});
  assert.equal(await form.locator("[data-permission-rows]").isHidden(), true);
  assert.match(await form.locator("[data-permission-status]").innerText(), /列表已更新/);
}

async function count(form) {
  return form.locator("xpath=ancestor::details[contains(@class,'node-permission-card')]")
    .locator("[data-permission-list] .permission-row").count();
}

async function capture(page, form, name) {
  const overflow = await page.evaluate(() => ({width: innerWidth, scroll: document.documentElement.scrollWidth}));
  assert.ok(overflow.scroll <= overflow.width + 1, `${name}: horizontal overflow ${JSON.stringify(overflow)}`);
  if (overflow.width < 768) {
    for (const button of await form.locator("button").all()) {
      if (!(await button.isVisible())) continue;
      const box = await button.boundingBox();
      assert.ok(box.height >= 44, `${name}: mobile button ${await button.innerText()} is only ${box.height}px tall`);
    }
    const lastButton = form.locator("button:visible").last();
    await lastButton.evaluate(button => button.scrollIntoView({block: "center"}));
    assert.equal(await lastButton.evaluate(button => {
      const box = button.getBoundingClientRect();
      const hit = document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2);
      return hit === button || button.contains(hit);
    }), true, `${name}: bottom actions must be reachable above fixed mobile navigation`);
  }
  // Capture the real viewport before element screenshots scroll the page. The
  // latter may stitch tall forms and include a fixed mobile bar mid-image.
  await page.screenshot({path: path.join(directory, `${name}-viewport.png`)});
  report.screenshots.push(`${name}-viewport.png`);
  await form.locator("xpath=ancestor::details[contains(@class,'permission-add-panel')]")
    .screenshot({path: path.join(directory, `${name}.png`)});
  report.screenshots.push(`${name}.png`);
}

async function normalFlow(browser, label, width) {
  const {context, page, navigations, requests} = await session(browser, width);
  try {
    const other = await editor(page, "home-desktop");
    await rule(other, 0, "vps", "tcp", "442");
    const form = await editor(page);
    await rule(form, 0, "vps", "tcp", "9080,22");
    await form.locator("[data-permission-add]").click();
    await rule(form, 1, "home-desktop", "udp", "8000-8002");
    await form.locator("[data-permission-add]").click();
    await rule(form, 2, "nas-storage-primary", "all");
    assert.equal(await form.locator("[data-permission-row]").count(), 3);
    assert.equal(await form.locator('[name="ports"]').nth(2).isDisabled(), true);
    await capture(page, form, `${label}-${width}-draft`);
    await preview(form);
    assert.match(await form.locator("[data-permission-review-facts]").innerText(), /iphone-travel/);
    assert.match(await form.locator("[data-permission-confirm]").innerText(), /3/);
    await capture(page, form, `${label}-${width}-review`);
    await form.locator("[data-permission-edit]").click();
    assert.equal(await form.locator('[name="ports"]').nth(0).inputValue(), "9080,22");
    assert.equal(await form.locator('[name="ports"]').nth(1).inputValue(), "8000-8002");
    assert.equal(await form.locator('[name="port_mode"]').nth(2).inputValue(), "all");
    await preview(form);
    await form.locator("[data-permission-confirm]").evaluate(button => { button.click(); button.click(); });
    await success(form);
    assert.equal(await count(form), 5);
    assert.equal(await other.locator('[name="ports"]').inputValue(), "442");
    assert.equal(await other.locator('[name="ports"]').isEnabled(), true);
    assert.equal(requests.filter(item => item.url.endsWith("/execute/")).length, 1);
    assert.deepEqual(navigations, []);
    await capture(page, form, `${label}-${width}-success`);
    await form.locator("[data-permission-continue]").click();
    assert.equal(await form.locator("[data-permission-row]").count(), 1);
    assert.equal(await form.locator('[name="ports"]').inputValue(), "");
    assert.equal(await other.locator('[name="ports"]').inputValue(), "442");
    report.checks.push(`${label} ${width}px: 3-rule preview/edit/one-confirm/no-navigation/list update/other draft preserved`);
  } finally { await context.close(); }
}

async function failures(browser, label) {
  const {context, page, navigations, requests} = await session(browser, 390);
  try {
    const form = await editor(page);
    await rule(form, 0, "vps", "tcp", "9000-8000");
    await form.locator("[data-permission-preview]").click();
    await form.locator("[data-permission-error]").waitFor({state: "visible"});
    assert.equal(await form.locator('[name="ports"]').inputValue(), "9000-8000");
    assert.equal(await form.locator('[name="ports"]').isEnabled(), true);
    assert.equal(await count(form), 2);
    await capture(page, form, `${label}-390-preview-error`);
    await rule(form, 0, "vps", "tcp", "22,9080");
    await preview(form);
    await page.route(`**${batchPath}execute/`, async route => {
      const response = await route.fetch();
      assert.equal(response.status(), 200);
      await route.abort("connectionclosed");
    });
    await form.locator("[data-permission-confirm]").click();
    await form.locator("[data-permission-retry]").waitFor({state: "visible"});
    assert.match(await form.locator("[data-permission-status]").innerText(), /不会自动重复提交/);
    assert.equal(await count(form), 2);
    await delay(2300);
    assert.equal(requests.filter(item => item.url.endsWith("/execute/")).length, 1);
    assert.equal(requests.filter(item => item.method === "GET").length, 0);
    await capture(page, form, `${label}-390-confirm-response-lost`);
    await form.locator("[data-permission-retry]").click();
    await success(form);
    assert.equal(await count(form), 3);
    assert.equal(requests.filter(item => item.url.endsWith("/execute/")).length, 1);
    assert.deepEqual(navigations, []);
    report.checks.push(`${label}: invalid preview retains draft; accepted-but-lost confirmation is never auto-resubmitted; manual status recovers`);
  } finally { await context.close(); }
}

async function pollingAndXss(browser, label) {
  const {context, page, requests, navigations} = await session(browser, 390);
  try {
    const form = await editor(page);
    await rule(form, 0, "vps", "tcp", "22,9080");
    await page.route(`**${batchPath}preview/`, async route => {
      const response = await route.fetch();
      const data = await response.json();
      data.task.preview.title = marker;
      data.task.preview.facts[marker] = marker;
      await route.fulfill({response, json: data});
    });
    await preview(form);
    assert.equal(await form.locator("[data-permission-review-title]").innerText(), marker);
    assert.equal(await form.locator("[data-permission-review] img").count(), 0);
    let polls = 0;
    await page.route(new RegExp(`${batchPath}task-[a-f0-9]+/$`), async route => {
      polls++;
      if (polls === 2) return route.fulfill({status: 503, contentType: "application/json", body: JSON.stringify({error: "模拟短暂断线"})});
      const response = await route.fetch();
      const data = await response.json();
      if (polls === 1) {
        data.task.state = "running"; data.task.terminal = false;
        data.task.progress = {message: "正在应用批量规则（模拟进度）"};
        delete data.permissions;
      } else {
        data.permissions[0].target_label = marker;
        data.permissions[0].ports_label = marker;
      }
      await route.fulfill({response, json: data});
    });
    await form.locator("[data-permission-confirm]").click();
    await form.locator("[data-permission-status]").filter({hasText: "模拟进度"}).waitFor();
    assert.equal(await count(form), 2);
    await capture(page, form, `${label}-390-running`);
    await form.locator("[data-permission-retry]").waitFor({state: "visible"});
    assert.match(await form.locator("[data-permission-error]").innerText(), /模拟短暂断线/);
    assert.equal(await count(form), 2);
    await capture(page, form, `${label}-390-status-error`);
    await form.locator("[data-permission-retry]").click();
    await success(form);
    assert.equal(await count(form), 3);
    assert.equal(requests.filter(item => item.url.endsWith("/execute/")).length, 1);
    assert.equal(await page.evaluate(() => window.__permissionXss), undefined);
    const card = form.locator("xpath=ancestor::details[contains(@class,'node-permission-card')]");
    assert.equal(await card.locator("[data-permission-list] img").count(), 0);
    assert.match(await card.locator("[data-permission-list]").innerText(), /onerror=/);
    assert.deepEqual(navigations, []);
    report.checks.push(`${label}: running status does not prematurely update ACL; polling error manual retry succeeds; preview and permission values render as text, not HTML`);
  } finally { await context.close(); }
}

async function rowLimits(browser) {
  const {context, page} = await session(browser, 320);
  try {
    const form = await editor(page);
    await form.locator("[data-permission-add]").evaluate(button => { for (let count = 0; count < 25; count++) button.click(); });
    assert.equal(await form.locator("[data-permission-row]").count(), 20);
    assert.equal(await form.locator("[data-permission-add]").isDisabled(), true);
    await form.locator("[data-permission-remove]").last().click();
    assert.equal(await form.locator("[data-permission-row]").count(), 19);
    assert.equal(await form.locator("[data-permission-add]").isEnabled(), true);
    assert.equal(await form.locator("[data-rule-number]").last().innerText(), "19");
    await capture(page, form, "chromium-320-many-rows");
    report.checks.push("320px: 20-row cap, removal/renumber/focus and no horizontal overflow");
  } finally { await context.close(); }
}

async function incompleteRecovery(browser, label) {
  const {context, page, requests, navigations} = await session(browser, 390);
  try {
    const form = await editor(page);
    await rule(form, 0, "vps", "tcp", "22,9080");
    await form.locator("[data-permission-add]").click();
    await rule(form, 1, "home-desktop", "udp", "8100-8102");
    await preview(form);
    await page.route(new RegExp(`${batchPath}task-[a-f0-9]+/$`), async route => {
      const response = await route.fetch();
      const data = await response.json();
      data.task.state = "failed";
      data.task.state_label = "失败";
      data.task.terminal = true;
      data.task.error = {code: "permission_recovery_required", message: "模拟自动回滚未完成：请保持现有管理连接并人工核验权限。"};
      delete data.permissions;
      await route.fulfill({response, json: data});
    });
    await form.locator("[data-permission-confirm]").click();
    await form.locator("[data-permission-status]").filter({hasText: "自动恢复尚未完成"}).waitFor();
    assert.match(await form.locator("[data-permission-error]").innerText(), /模拟自动回滚未完成/);
    assert.equal(await count(form), 2, "An uncertain rollback must not replace the visible ACL");
    for (const action of ["edit", "continue", "confirm", "preview", "add", "retry"]) {
      assert.equal(await form.locator(`[data-permission-${action}]`).isVisible(), false, `${action} must not be exposed after incomplete recovery`);
    }
    assert.equal(await form.locator('[name="ports"]').nth(0).inputValue(), "22,9080");
    assert.equal(await form.locator('[name="ports"]').nth(1).inputValue(), "8100-8102");
    assert.equal(await form.locator('[name="ports"]').nth(0).isDisabled(), true);
    assert.equal(await form.locator('[name="ports"]').nth(1).isDisabled(), true);
    const link = form.locator("[data-permission-task-link]");
    assert.equal(await link.isVisible(), true);
    assert.equal(await link.getAttribute("target"), "_blank");
    assert.match(await link.getAttribute("href"), /\/tasks\/task-[a-f0-9]+\/$/);
    await link.focus();
    assert.equal(await link.evaluate(node => document.activeElement === node), true);
    // Repeated submit/confirm events cannot queue another mutation while frozen.
    await form.evaluate(node => node.dispatchEvent(new Event("submit", {bubbles: true, cancelable: true})));
    await form.locator("[data-permission-confirm]").evaluate(button => button.click());
    await delay(2300);
    assert.equal(requests.filter(item => item.url.endsWith("/execute/")).length, 1);
    assert.equal(requests.filter(item => item.url.endsWith("/preview/")).length, 1);
    assert.equal(requests.filter(item => item.method === "GET").length, 1);
    assert.deepEqual(navigations, []);
    await page.screenshot({path: path.join(directory, `${label}-390-incomplete-recovery-viewport.png`)});
    report.screenshots.push(`${label}-390-incomplete-recovery-viewport.png`);
    report.checks.push(`${label}: incomplete automatic rollback freezes batch, retains disabled draft values and task link, never auto-retries or exposes a new submit`);
  } finally { await context.close(); }
}

(async () => {
  try {
    for (const [label, engine] of [["chromium", chromium], ["webkit", webkit]]) {
      const browser = await engine.launch({headless: true});
      try {
        await normalFlow(browser, label, 1440);
        await normalFlow(browser, label, 390);
        await failures(browser, label);
        await pollingAndXss(browser, label);
        await incompleteRecovery(browser, label);
        if (label === "chromium") await rowLimits(browser);
      } finally { await browser.close(); }
    }
    assert.deepEqual(report.errors, []);
    assert.deepEqual(report.blocked, []);
    console.log(JSON.stringify({...report, screenshotCount: report.screenshots.length}, null, 2));
  } catch (error) {
    report.failure = error.stack;
    console.error(error.stack);
    process.exitCode = 1;
  } finally {
    fs.writeFileSync(path.join(directory, "report.json"), JSON.stringify(report, null, 2));
    console.log(`Permission QA artifacts: ${directory}`);
  }
})();
