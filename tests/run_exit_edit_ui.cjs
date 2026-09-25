"use strict";

// Browser regression for local, synthetic fixtures only; never targets a VPS.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {chromium, webkit} = require("playwright");
const base = new URL(process.argv[2] || "http://127.0.0.1:8765/");
if (base.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(base.hostname)
    || base.username || base.password || base.pathname !== "/") throw new Error("Only an isolated loopback preview is allowed.");
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "server-kit-exit-edit-"));
const report = {directory, checks: [], screenshots: [], errors: [], blocked: []};
const password = "Preview-only-2026!";
const secret = "synthetic-preview-exit-secret";
const originalName = "dedicated-us-primary";
const firstId = "333333333333", advancedId = "444444444444";
const endpoint = id => new URL(`network/proxy/${id}/exit/`, base).href;
const editor = (page, id = firstId) => page.locator(`form[data-exit-edit-form]:has(input[name="exit_id"][value="${id}"])`);
const field = (form, name) => form.locator(`[name="${name}"]`);
const loader = form => form.locator('[data-secret-action="edit-exit"]');
const auth = page => page.locator("[data-sensitive-auth-modal]");
const taskModal = page => page.locator("[data-inline-task-modal]");
const details = form => form.locator("xpath=ancestor::details[1]");
const fieldsMode = form => form.locator('[name="exit_input_mode"][value="fields"]');
const fieldsLabel = form => fieldsMode(form).locator("xpath=ancestor::label[1]");

async function selectFields(form, width = 390, allowDisabled = false) {
  // Tap visible label text so the browser performs native label activation.
  // Waiting for this target to settle also handles mobile focus/scroll changes.
  const target = fieldsLabel(form).locator("strong");
  if (width < 768) await target.tap({force: allowDisabled});
  else await target.click({force: allowDisabled});
}

async function session(browser, width = 390, username = "preview") {
  const context = await browser.newContext({viewport: {width, height: width < 768 ? 844 : 1000},
    ...(width < 768 ? {isMobile: true, hasTouch: true} : {})});
  await context.route("**/*", route => {
    if (new URL(route.request().url()).origin === base.origin) return route.continue();
    report.blocked.push(route.request().url());
    return route.abort();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  page.on("pageerror", error => report.errors.push(error.message));
  const dialogs = [];
  const answers = [];
  page.on("dialog", async dialog => {
    dialogs.push(dialog.message());
    if (answers.shift() === false) await dialog.dismiss();
    else await dialog.accept();
  });
  await page.goto(new URL("login/", base).href);
  await field(page, "username").fill(username);
  await field(page, "password").fill(password);
  await Promise.all([page.waitForURL(base.href), page.locator('button[type="submit"]').click()]);
  assert.equal((await context.request.get(new URL("__preview__/scenario/rich/", base).href)).status(), 200);
  await page.goto(new URL("network/proxy/", base).href);
  const navigations = [], requests = [];
  page.on("framenavigated", frame => { if (frame === page.mainFrame()) navigations.push(frame.url()); });
  page.on("request", request => requests.push({url: request.url(), method: request.method()}));
  return {context, page, navigations, requests, dialogs, answers};
}

async function open(form) {
  if (await details(form).getAttribute("open") === null) await details(form).locator(":scope > summary").click();
  await field(form, "exit_name").waitFor({state: "visible"});
}

async function screenshot(page, label) {
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true, `${label}: page overflow`);
  const visibleDialog = page.locator('[role="dialog"]:visible');
  if (await visibleDialog.count()) assert.equal(await visibleDialog.evaluate(node => node.scrollWidth <= node.clientWidth + 1), true, `${label}: dialog overflow`);
  await page.screenshot({path: path.join(directory, label + ".png")});
  report.screenshots.push(label + ".png");
}

async function unlock(page) {
  await auth(page).waitFor({state: "visible"});
  await field(auth(page), "password").fill(password);
  await auth(page).locator('button[type="submit"]').click();
  await auth(page).waitFor({state: "hidden"});
}

async function unlockDirect(context, page) {
  const csrf = await field(page, "csrfmiddlewaretoken").first().inputValue();
  const response = await context.request.post(new URL("sensitive/unlock/", base).href,
    {headers: {Accept: "application/json"}, form: {csrfmiddlewaretoken: csrf, password, destination: "proxy"}});
  assert.equal(response.status(), 200);
}

async function loaded(form) {
  await form.page().waitForFunction(id => {
    const form = [...document.querySelectorAll("[data-exit-edit-form]")].find(form => form.elements.exit_id.value === id);
    return Boolean(form.elements.exit_proxy_yaml.value);
  }, await field(form, "exit_id").inputValue());
}

async function fieldsAvailable(form) {
  await form.page().waitForFunction(id => {
    const form = [...document.querySelectorAll("[data-exit-edit-form]")].find(form => form.elements.exit_id.value === id);
    return !form.querySelector('[name="exit_input_mode"][value="fields"]').disabled;
  }, await field(form, "exit_id").inputValue());
}

async function noStoredSecrets(page) {
  assert.doesNotMatch(await page.evaluate(() => JSON.stringify({local: {...localStorage}, session: {...sessionStorage}})), /synthetic-preview-exit-secret|Preview-only-2026/);
  assert.doesNotMatch(await taskModal(page).innerHTML(), /synthetic-preview-exit-secret|synthetic-preview-user/);
  assert.doesNotMatch(await page.locator("[data-secret-modal]").innerHTML(), /synthetic-preview-exit-secret/);
}

async function cleared(form) {
  for (const name of ["exit_proxy_yaml", "exit_proxy_base", "exit_field_username", "exit_field_password", "password"]) {
    assert.equal(await field(form, name).inputValue(), "", `${name} cleared`);
  }
  assert.equal(await field(form, "confirmed").isChecked(), false);
  assert.equal(await field(form, "exit_input_mode").count(), 2);
  assert.equal(await fieldsMode(form).isEnabled(), true);
}

async function directFieldsClick(browser, label, width) {
  const {context, page, requests, navigations} = await session(browser, width);
  try {
    const form = editor(page);
    await open(form);
    const defaultValue = await field(form, "exit_default").inputValue();
    await field(form, "exit_name").fill("fields-click-draft-name");
    const reads = () => requests.filter(item => item.url === endpoint(firstId)).length;
    assert.equal(reads(), 0, "opening an editor must not reveal existing credentials");
    assert.equal(await fieldsMode(form).isEnabled(), true, "blank editor must accept the real fields label click");
    await selectFields(form, width);
    await auth(page).waitFor({state: "visible"});
    assert.equal(await form.locator('[name="exit_input_mode"][value="yaml"]').isChecked(), true);
    assert.equal(await field(form, "exit_proxy_yaml").inputValue(), "");
    await screenshot(page, `${label}-${width}-direct-fields-auth`);
    await field(auth(page), "password").fill("cancelled-fields-password");
    await auth(page).locator(".qr-close[data-sensitive-auth-close]").click();
    await fieldsAvailable(form);
    await cleared(form);
    assert.equal(await field(auth(page), "password").inputValue(), "");
    assert.equal(await field(form, "exit_name").inputValue(), "fields-click-draft-name");
    assert.equal(await field(form, "exit_default").inputValue(), defaultValue);
    assert.equal(reads(), 1);

    // Retrying the same visible control must re-enter the established password flow.
    await selectFields(form, width);
    await auth(page).waitFor({state: "visible"});
    await field(auth(page), "password").fill("wrong-fields-password");
    await auth(page).locator('button[type="submit"]').click();
    await auth(page).locator("[data-sensitive-auth-error]").waitFor({state: "visible"});
    assert.match(await auth(page).locator("[data-sensitive-auth-error]").innerText(), /密码/);
    assert.equal(await field(form, "exit_proxy_yaml").inputValue(), "");
    assert.equal(reads(), 2, "wrong password cannot reveal a configuration");
    await screenshot(page, `${label}-${width}-direct-fields-wrong-password`);
    await unlock(page);
    await loaded(form);
    await fieldsAvailable(form);
    assert.equal(await fieldsMode(form).isChecked(), true);
    assert.equal(await field(form, "exit_name").inputValue(), "fields-click-draft-name");
    assert.equal(await field(form, "exit_default").inputValue(), defaultValue);
    assert.equal(await field(form, "exit_field_server").inputValue(), "us-egress.example");
    assert.equal(await field(form, "exit_field_password").inputValue(), secret);
    assert.equal(await field(form, "exit_field_password").getAttribute("type"), "password");
    assert.equal(await field(auth(page), "password").inputValue(), "");
    assert.equal(reads(), 3);
    await noStoredSecrets(page);
    await screenshot(page, `${label}-${width}-direct-fields-loaded`);
    assert.deepEqual(navigations, []);
    report.checks.push(`${label} ${width}: physical fields ${width < 768 ? "touch" : "click"} opens password unlock; cancellation/wrong password preserve the draft; retry loads SOCKS5 without navigation`);
  } finally { await context.close(); }
}

async function alreadyUnlockedFieldsClick(browser, label) {
  const {context, page, requests, navigations} = await session(browser);
  let release;
  try {
    const form = editor(page);
    await open(form);
    await unlockDirect(context, page);
    let reached;
    const pending = new Promise(resolve => { release = resolve; });
    const intercepted = new Promise(resolve => { reached = resolve; });
    await page.route(endpoint(firstId), async route => {
      const response = await route.fetch();
      assert.equal(response.status(), 200);
      reached();
      await pending;
      await route.fulfill({response});
    });
    await selectFields(form);
    await intercepted;
    assert.equal(await fieldsMode(form).isDisabled(), true, "loading disables another fields request");
    assert.equal(await form.locator('[name="exit_input_mode"][value="yaml"]').isChecked(), true);
    assert.equal(await field(form, "exit_proxy_yaml").inputValue(), "");
    assert.equal(await auth(page).isVisible(), false);
    await selectFields(form, 390, true);
    assert.equal(requests.filter(item => item.url === endpoint(firstId)).length, 1);
    await screenshot(page, `${label}-390-direct-fields-loading`);
    release();
    await loaded(form);
    await fieldsAvailable(form);
    assert.equal(await fieldsMode(form).isChecked(), true);
    assert.equal(await auth(page).isVisible(), false);
    assert.equal(await field(form, "exit_field_password").inputValue(), secret);
    assert.equal(requests.filter(item => item.url === endpoint(firstId)).length, 1);
    await noStoredSecrets(page);
    assert.deepEqual(navigations, []);
    report.checks.push(`${label}: already-unlocked fields touch starts one request, shows loading, then enables and selects populated fields`);
  } finally { release?.(); await context.close(); }
}

async function keyboardFieldsSelection(browser, label) {
  const {context, page, requests, navigations} = await session(browser, 1440);
  try {
    const form = editor(page);
    await open(form);
    const yaml = form.locator('[name="exit_input_mode"][value="yaml"]');
    await yaml.focus();
    await page.keyboard.press("ArrowLeft");
    await auth(page).waitFor({state: "visible"});
    assert.equal(await yaml.isChecked(), true);
    await auth(page).locator(".qr-close[data-sensitive-auth-close]").click();
    await fieldsAvailable(form);
    await fieldsMode(form).focus();
    await page.keyboard.press("Space");
    await auth(page).waitFor({state: "visible"});
    await unlock(page);
    await loaded(form);
    await fieldsAvailable(form);
    assert.equal(await fieldsMode(form).isChecked(), true);
    assert.equal(await field(form, "exit_field_server").inputValue(), "us-egress.example");
    assert.equal(requests.filter(item => item.url === endpoint(firstId)).length, 3);
    assert.deepEqual(navigations, []);
    report.checks.push(`${label}: native radio arrow-key and Space selection both enter the password flow and allow a loaded fields editor`);
  } finally { await context.close(); }
}

async function preservedFieldsDrafts(browser, label) {
  const {context, page, requests, navigations, dialogs} = await session(browser);
  try {
    const form = editor(page), advanced = editor(page, advancedId);
    await open(advanced);
    await selectFields(advanced);
    assert.equal(await fieldsMode(advanced).isEnabled(), true);
    assert.equal(await advanced.locator('[name="exit_input_mode"][value="yaml"]').isChecked(), true);
    assert.equal(await field(advanced, "exit_proxy_yaml").inputValue(), "");
    const unsupportedStatus = await advanced.locator("[data-exit-edit-status]").innerText();
    assert.match(unsupportedStatus, /SOCKS5/);
    assert.match(unsupportedStatus, /完整配置/);
    assert.equal(await page.locator("[data-interaction-feedback]").innerText(), unsupportedStatus);
    assert.equal(await auth(page).isVisible(), false);
    assert.equal(requests.filter(item => item.url === endpoint(advancedId)).length, 0);
    await screenshot(page, `${label}-390-direct-fields-vless-reason`);

    await open(form);
    await field(form, "exit_name").fill("manual-fields-draft");
    for (const [kind, draft] of [
      ["yaml", "type: socks5\nserver: draft-synthetic.example\nport: 1080\nusername: draft-user\npassword: draft-secret\nudp: false\n"],
      ["unsupported-json", JSON.stringify({type: "vless", server: "draft-synthetic.example", port: 443, uuid: "synthetic-id", "ws-opts": {path: "/preserve"}})],
      ["invalid-socks5-json", JSON.stringify({type: "socks5", server: "draft-synthetic.example", port: 1080, username: "unpaired-synthetic-user"})],
    ]) {
      await field(form, "exit_proxy_yaml").fill(draft);
      await selectFields(form);
      assert.equal(await fieldsMode(form).isEnabled(), true);
      assert.equal(await form.locator('[name="exit_input_mode"][value="yaml"]').isChecked(), true);
      assert.equal(await field(form, "exit_proxy_yaml").inputValue(), draft, `${kind}: fields click preserves every draft byte`);
      assert.equal(await field(form, "exit_name").inputValue(), "manual-fields-draft");
      assert.equal(await field(form, "exit_proxy_base").inputValue(), "");
      assert.equal(await field(form, "exit_field_password").inputValue(), "");
      const status = await form.locator("[data-exit-edit-status]").innerText();
      assert.match(status, /完整配置/);
      assert.equal(await page.locator("[data-interaction-feedback]").innerText(), status);
      assert.equal(await auth(page).isVisible(), false);
      assert.equal(requests.filter(item => item.url === endpoint(firstId)).length, 0);
      await screenshot(page, `${label}-390-direct-fields-${kind}-reason`);
    }
    const pasted = {type: "socks5", server: "pasted-synthetic.example", port: 2080,
      username: "pasted-user", password: "pasted-secret", udp: false, tls: true, "skip-cert-verify": false};
    await field(form, "exit_proxy_yaml").fill(JSON.stringify(pasted, null, 2) + "\n");
    await selectFields(form);
    assert.equal(await fieldsMode(form).isChecked(), true);
    assert.deepEqual(JSON.parse(await field(form, "exit_proxy_base").inputValue()), pasted);
    assert.match(await form.locator("[data-exit-edit-status]").innerText(), /已转为字段/);
    assert.doesNotMatch(await form.locator("[data-exit-edit-status]").innerText(), /无法安全转换/);
    assert.equal(await field(form, "exit_field_password").inputValue(), pasted.password);
    assert.equal(await auth(page).isVisible(), false);
    assert.equal(requests.filter(item => item.url === endpoint(firstId)).length, 0);
    assert.deepEqual(dialogs, [], "fields mode selection must never request draft replacement");
    assert.deepEqual(navigations, []);
    report.checks.push(`${label}: initial VLESS and incompatible drafts show inline/toast reasons without requests; valid pasted SOCKS5 enters fields and retains advanced parameters locally`);
  } finally { await context.close(); }
}

async function staffFieldsClick(browser, label) {
  const {context, page, requests, navigations} = await session(browser, 390, "administrator-with-long-name");
  try {
    const form = editor(page);
    await open(form);
    assert.equal(await loader(form).count(), 0);
    assert.equal(await fieldsMode(form).isEnabled(), true);
    await selectFields(form);
    assert.equal(await form.locator('[name="exit_input_mode"][value="yaml"]').isChecked(), true);
    const status = await form.locator("[data-exit-edit-status]").innerText();
    assert.match(status, /超级管理员/);
    assert.equal(await page.locator("[data-interaction-feedback]").innerText(), status);
    assert.equal(await auth(page).isVisible(), false);
    assert.equal(requests.filter(item => item.url === endpoint(firstId)).length, 0);
    const pasted = {type: "socks5", server: "staff-draft.example", port: 1080, udp: false};
    await field(form, "exit_proxy_yaml").fill(JSON.stringify(pasted));
    await selectFields(form);
    assert.equal(await fieldsMode(form).isChecked(), true);
    assert.deepEqual(JSON.parse(await field(form, "exit_proxy_base").inputValue()), pasted);
    assert.equal(requests.filter(item => item.url === endpoint(firstId)).length, 0);
    assert.deepEqual(navigations, []);
    await screenshot(page, `${label}-390-staff-pasted-fields`);
    report.checks.push(`${label}: staff receives a visible explanation without a reveal request and can edit pasted SOCKS5 fields`);
  } finally { await context.close(); }
}

async function complete(page, form) {
  await field(form, "password").fill(password);
  await field(form, "confirmed").check();
  await form.locator('button[type="submit"]').click();
  await taskModal(page).locator("[data-inline-confirm]").waitFor({state: "visible"});
  assert.equal(await fieldsMode(form).isDisabled(), true, "previewed form keeps mode selection locked until released");
  await noStoredSecrets(page);
  await taskModal(page).locator("[data-inline-confirm]").click();
  await taskModal(page).locator("[data-inline-done]").waitFor({state: "visible"});
  assert.match(await taskModal(page).locator("[data-inline-status]").innerText(), /已保存/);
  await taskModal(page).locator("[data-inline-done]").click();
  await taskModal(page).waitFor({state: "hidden"});
}

function submittedField(request, name) {
  const body = request.postData() || "";
  if ((request.headers()["content-type"] || "").includes("application/x-www-form-urlencoded")) return new URLSearchParams(body).get(name);
  const match = body.match(new RegExp(`name="${name}"\\r\\n\\r\\n([\\s\\S]*?)\\r\\n--`));
  return match ? match[1] : null;
}

async function editLifecycle(browser, label, width) {
  const {context, page, navigations, requests} = await session(browser, width);
  try {
    let form = editor(page);
    await open(form);
    assert.match(await details(form).locator(":scope > summary").innerText(), /^编辑出口/);
    assert.equal(await field(form, "exit_name").inputValue(), originalName);
    await cleared(form);
    assert.equal(await field(form, "exit_proxy_yaml").getAttribute("required"), null);
    assert.equal(await form.locator('[name="exit_input_mode"][value="yaml"]').isChecked(), true);
    assert.equal(await loader(form).innerText(), "载入现有配置");
    await noStoredSecrets(page);

    // Renaming never needs to reveal or re-submit the existing proxy credentials.
    await field(form, "exit_name").fill("renamed-synthetic-us");
    await complete(page, form);
    assert.equal(requests.filter(item => item.url === endpoint(firstId)).length, 0);
    form = editor(page);
    await open(form);
    assert.equal(await field(form, "exit_name").inputValue(), "renamed-synthetic-us");
    await cleared(form);

    // Cancelling authentication keeps the user's name/default selection and draft.
    await field(form, "exit_name").fill("draft-synthetic-us");
    const defaultValue = await field(form, "exit_default").inputValue();
    await loader(form).click();
    await auth(page).waitFor({state: "visible"});
    await field(auth(page), "password").fill("cancelled-demo-password");
    await auth(page).locator(".qr-close[data-sensitive-auth-close]").click();
    assert.equal(await field(auth(page), "password").inputValue(), "");
    assert.equal(await field(form, "exit_name").inputValue(), "draft-synthetic-us");
    assert.equal(await field(form, "exit_proxy_yaml").inputValue(), "");

    await loader(form).click();
    await auth(page).waitFor({state: "visible"});
    await field(auth(page), "password").fill("wrong-demo-password");
    await auth(page).locator('button[type="submit"]').click();
    await auth(page).locator("[data-sensitive-auth-error]").waitFor({state: "visible"});
    assert.match(await auth(page).locator("[data-sensitive-auth-error]").innerText(), /密码/);
    await screenshot(page, `${label}-${width}-unlock-error`);
    await unlock(page);
    await loaded(form);
    assert.equal(await field(auth(page), "password").inputValue(), "");
    assert.equal(await field(form, "exit_name").inputValue(), "draft-synthetic-us");
    assert.equal(await field(form, "exit_default").inputValue(), defaultValue);
    assert.equal(await field(form, "exit_field_server").inputValue(), "us-egress.example");
    assert.equal(await field(form, "exit_field_port").inputValue(), "1080");
    assert.equal(await field(form, "exit_field_username").inputValue(), "synthetic-preview-user");
    assert.equal(await field(form, "exit_field_password").inputValue(), secret);
    assert.equal(await field(form, "exit_field_password").getAttribute("type"), "password");
    const expected = JSON.parse(await field(form, "exit_proxy_base").inputValue());
    assert.equal(expected.udp, false);
    assert.equal(expected.tls, true);
    await form.locator('[name="exit_input_mode"][value="fields"]').check();
    await field(form, "exit_field_server").fill("edited-synthetic.example");
    await field(form, "exit_field_port").fill("1088");
    await form.locator('[name="exit_input_mode"][value="yaml"]').check();
    assert.deepEqual(JSON.parse(await field(form, "exit_proxy_yaml").inputValue()), {...expected, server: "edited-synthetic.example", port: 1088});
    await form.locator('[name="exit_input_mode"][value="fields"]').check();
    await screenshot(page, `${label}-${width}-loaded-socks5`);
    let submitted;
    const capture = request => {
      if (new URL(request.url()).pathname === "/network/proxy/" && request.method() === "POST") {
        submitted = {base: submittedField(request, "exit_proxy_base"), server: submittedField(request, "exit_field_server"),
          port: submittedField(request, "exit_field_port"), mode: submittedField(request, "exit_input_mode")};
      }
    };
    page.on("request", capture);
    await complete(page, form);
    page.off("request", capture);
    assert.equal(submitted.mode, "fields");
    assert.equal(submitted.server, "edited-synthetic.example");
    assert.equal(submitted.port, "1088");
    assert.deepEqual(JSON.parse(submitted.base), {...expected, server: "edited-synthetic.example", port: 1088});
    form = editor(page);
    await open(form);
    await cleared(form);
    assert.equal(await field(form, "exit_name").inputValue(), "draft-synthetic-us");
    await noStoredSecrets(page);
    const response = await context.request.get(new URL("network/proxy/", base).href);
    assert.doesNotMatch(await response.text(), /synthetic-preview-exit-secret|synthetic-preview-user/);
    assert.deepEqual(navigations, []);
    report.checks.push(`${label} ${width}: blank rename without reveal; cancel/wrong-password/unlock; preserved name/default and extra proxy fields; inline save clears secrets without navigation`);
  } finally { await context.close(); }
}

async function modesAndCancel(browser, label) {
  const {context, page, navigations, requests, dialogs, answers} = await session(browser);
  try {
    const form = editor(page);
    await open(form);
    await unlockDirect(context, page);
    await loader(form).click();
    await loaded(form);
    await form.locator('[name="exit_input_mode"][value="fields"]').check();
    await field(form, "exit_field_server").fill("keep-draft.example");
    await field(form, "exit_name").fill("keep-draft-name");
    const defaultValue = await field(form, "exit_default").inputValue();
    const reads = () => requests.filter(item => item.url === endpoint(firstId)).length;
    const before = reads();
    answers.push(false);
    await loader(form).click();
    assert.ok(dialogs.length, "loading over a changed proxy asks before replacing it");
    assert.equal(reads(), before);
    assert.equal(await field(form, "exit_field_server").inputValue(), "keep-draft.example");
    answers.push(true);
    await Promise.all([page.waitForResponse(endpoint(firstId)), loader(form).click()]);
    await page.waitForFunction(() => document.querySelector('[data-exit-edit-form] [name="exit_field_server"]').value === "us-egress.example");
    assert.equal(await field(form, "exit_name").inputValue(), "keep-draft-name");
    assert.equal(await field(form, "exit_default").inputValue(), defaultValue);

    await form.locator('[name="exit_input_mode"][value="yaml"]').check();
    await field(form, "exit_proxy_yaml").fill("type: socks5\nserver: manual-draft.example\nport: 1080\npassword: manual-synthetic-secret\nudp: false\n");
    assert.equal(await fieldsMode(form).isEnabled(), true);
    await field(form, "password").fill(password);
    await field(form, "confirmed").check();
    await form.locator("[data-exit-edit-cancel]").click();
    assert.equal(await details(form).getAttribute("open"), null);
    await cleared(form);
    await open(form);
    assert.equal(await field(form, "exit_name").inputValue(), originalName);
    assert.equal(await field(form, "exit_default").inputValue(), defaultValue);
    await cleared(form);

    const advanced = editor(page, advancedId);
    await open(advanced);
    await field(advanced, "exit_default").check();
    await loader(advanced).click();
    await loaded(advanced);
    assert.match(await field(advanced, "exit_proxy_yaml").inputValue(), /type: "?vless/);
    assert.match(await field(advanced, "exit_proxy_yaml").inputValue(), /ws-opts:/);
    assert.equal(await advanced.locator('[name="exit_input_mode"][value="yaml"]').isChecked(), true);
    assert.equal(await fieldsMode(advanced).isEnabled(), true);
    assert.equal(await field(advanced, "exit_name").inputValue(), "dedicated-eu-failover");
    assert.equal(await field(advanced, "exit_default").isChecked(), true);
    await noStoredSecrets(page);
    await screenshot(page, `${label}-390-advanced-yaml`);
    await advanced.locator("[data-exit-edit-cancel]").click();
    await cleared(advanced);
    assert.deepEqual(navigations, []);
    report.checks.push(`${label}: repeated-load confirmation keeps dirty edits on decline; manual YAML keeps the mode control actionable; cancel resets and clears credentials; advanced VLESS remains complete YAML`);
  } finally { await context.close(); }
}

async function delayedReveal(browser, label) {
  const {context, page, navigations} = await session(browser);
  try {
    const form = editor(page);
    await open(form);
    await unlockDirect(context, page);
    for (const scenario of ["changed", "cancelled"]) {
      let release, reached, delivered;
      const pending = new Promise(resolve => { release = resolve; });
      const intercepted = new Promise(resolve => { reached = resolve; });
      const responseHandled = new Promise(resolve => { delivered = resolve; });
      const handler = async route => {
        const response = await route.fetch();
        assert.equal(response.status(), 200);
        assert.match(response.headers()["cache-control"], /no-store/);
        reached();
        await pending;
        try { await route.fulfill({response}); } finally { delivered(); }
      };
      await page.route(endpoint(firstId), handler);
      await loader(form).click();
      await intercepted;
      if (scenario === "cancelled") {
        await form.locator("[data-exit-edit-cancel]").click();
        await open(form);
      }
      const draft = "type: socks5\nserver: race-draft.example\nport: 1099\n";
      await field(form, "exit_proxy_yaml").fill(draft);
      await field(form, "exit_name").fill(`race-${scenario}`);
      release();
      await responseHandled;
      await page.waitForFunction(() => !document.querySelector('[data-exit-edit-form] [data-secret-action="edit-exit"]').disabled);
      assert.equal(await field(form, "exit_proxy_yaml").inputValue(), draft, `${scenario}: late reveal must preserve the new draft`);
      assert.equal(await field(form, "exit_proxy_base").inputValue(), "");
      assert.equal(await field(form, "exit_field_password").inputValue(), "");
      assert.equal(await field(form, "exit_name").inputValue(), `race-${scenario}`);
      await page.unroute(endpoint(firstId), handler);
      await form.locator("[data-exit-edit-cancel]").click();
      await open(form);
    }
    await noStoredSecrets(page);
    assert.deepEqual(navigations, []);
    report.checks.push(`${label}: delayed reveal cannot overwrite a changed draft or a cancelled/reopened editor`);
  } finally { await context.close(); }
}

async function delayedUnlock(browser, label) {
  const {context, page, navigations} = await session(browser);
  try {
    const form = editor(page);
    await open(form);
    let release, reached, delivered;
    const pending = new Promise(resolve => { release = resolve; });
    const intercepted = new Promise(resolve => { reached = resolve; });
    const responseHandled = new Promise(resolve => { delivered = resolve; });
    await page.route(endpoint(firstId), async route => {
      reached();
      await pending;
      try {
        await route.fulfill({status: 403, contentType: "application/json",
          body: JSON.stringify({code: "sensitive_unlock_required", error: "模拟短时解锁已过期"})});
      } finally { delivered(); }
    });
    await loader(form).click();
    await intercepted;
    await form.locator("[data-exit-edit-cancel]").click();
    await open(form);
    await field(form, "exit_name").fill("after-cancelled-auth");
    release();
    await responseHandled;
    await page.waitForFunction(() => !document.querySelector('[data-exit-edit-form] [data-secret-action="edit-exit"]').disabled);
    assert.equal(await auth(page).isVisible(), false, "cancelled reveal must not later request authentication");
    assert.equal(await field(form, "exit_name").inputValue(), "after-cancelled-auth");
    await cleared(form);
    assert.deepEqual(navigations, []);
    report.checks.push(`${label}: a delayed expired-unlock response cannot reopen authentication for a cancelled editor`);
  } finally { await context.close(); }
}

async function multilineCredentials(browser, label) {
  const {context, page, navigations} = await session(browser);
  try {
    const form = editor(page);
    await open(form);
    await unlockDirect(context, page);
    const proxy = {type: "socks5", server: "multiline-synthetic.example", port: 1080,
      username: "synthetic\r\nuser", password: "synthetic\npassword", udp: false, tls: true};
    const value = JSON.stringify(proxy, null, 2) + "\n";
    await page.route(endpoint(firstId), route => route.fulfill({status: 200, contentType: "application/json",
      body: JSON.stringify({item_id: firstId, value, proxy})}));
    await loader(form).click();
    await loaded(form);
    assert.equal(await field(form, "exit_proxy_yaml").inputValue(), value);
    assert.equal(await form.locator('[name="exit_input_mode"][value="yaml"]').isChecked(), true);
    assert.equal(await fieldsMode(form).isEnabled(), true);
    assert.equal(await field(form, "exit_proxy_base").inputValue(), "");
    assert.equal(await field(form, "exit_field_password").inputValue(), "");
    await selectFields(form);
    assert.equal(await field(form, "exit_proxy_yaml").inputValue(), value, "unsupported multiline credentials remain lossless after a fields touch");
    assert.equal(await form.locator('[name="exit_input_mode"][value="yaml"]').isChecked(), true);
    assert.match(await form.locator("[data-exit-edit-status]").innerText(), /完整配置/);
    assert.deepEqual(navigations, []);
    report.checks.push(`${label}: SOCKS5 credentials containing CR/LF stay intact in full configuration mode`);
  } finally { await context.close(); }
}

async function delayedAuthSuccess(browser, label) {
  for (const scenario of ["cancel", "pagehide"]) {
    const {context, page, navigations, requests} = await session(browser);
    try {
      const form = editor(page);
      await open(form);
      let release, reached;
      const pending = new Promise(resolve => { release = resolve; });
      const intercepted = new Promise(resolve => { reached = resolve; });
      const url = new URL("sensitive/unlock/", base).href;
      await page.route(url, async route => {
        const response = await route.fetch();
        assert.equal(response.status(), 200);
        reached();
        await pending;
        await route.fulfill({response});
      });
      await loader(form).click();
      await auth(page).waitFor({state: "visible"});
      await field(auth(page), "password").fill(password);
      await auth(page).locator('button[type="submit"]').click();
      await intercepted;
      if (scenario === "cancel") await form.locator("[data-exit-edit-cancel]").evaluate(button => button.click());
      else await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pagehide", {persisted: true})));
      await auth(page).waitFor({state: "hidden"});
      await open(form);
      await field(form, "exit_name").fill(`after-${scenario}-unlock`);
      const responseDelivered = page.waitForResponse(url);
      release();
      await responseDelivered;
      await page.waitForLoadState("networkidle");
      assert.equal(requests.filter(item => item.url === endpoint(firstId)).length, 1, "late unlock may not repeat cancelled reveal");
      assert.equal(await auth(page).isVisible(), false);
      assert.equal(await field(auth(page), "password").inputValue(), "");
      assert.equal(await field(form, "exit_name").inputValue(), `after-${scenario}-unlock`);
      await cleared(form);
      assert.equal(await loader(form).isEnabled(), true);
      assert.deepEqual(navigations, []);
    } finally { await context.close(); }
  }
  report.checks.push(`${label}: delayed successful authentication cannot restore an editor cancelled or cleared by pagehide`);
}

async function previewDuringLoad(browser, label) {
  const {context, page, navigations, requests} = await session(browser);
  try {
    const form = editor(page);
    await open(form);
    await unlockDirect(context, page);
    await field(form, "exit_name").fill("after-delayed-load");
    await field(form, "password").fill(password);
    await field(form, "confirmed").check();
    let release, reached;
    const pending = new Promise(resolve => { release = resolve; });
    const intercepted = new Promise(resolve => { reached = resolve; });
    await page.route(endpoint(firstId), async route => {
      const response = await route.fetch();
      reached();
      await pending;
      await route.fulfill({response});
    });
    await loader(form).click();
    await intercepted;
    await form.locator('button[type="submit"]').click();
    assert.equal(requests.filter(item => item.url === new URL("network/proxy/", base).href && item.method === "POST").length, 0);
    assert.equal(await taskModal(page).isVisible(), false);
    assert.match(await page.locator("[data-interaction-feedback]").innerText(), /正在载入/);
    release();
    await loaded(form);
    await page.waitForFunction(() => !document.querySelector('[data-exit-edit-form] [data-secret-action="edit-exit"]').disabled);
    await complete(page, form);
    await open(editor(page));
    await cleared(editor(page));
    assert.equal(await loader(editor(page)).isEnabled(), true);
    assert.equal(requests.filter(item => item.url === new URL("network/proxy/", base).href && item.method === "POST").length, 1);
    assert.deepEqual(navigations, []);
    report.checks.push(`${label}: preview is blocked during loading, then saves once and leaves the load button usable`);
  } finally { await context.close(); }
}

async function retainedCardAndPageHide(browser, label) {
  const {context, page, navigations} = await session(browser);
  try {
    await unlockDirect(context, page);
    for (const [id, operation] of [[firstId, "exit_delete"], [advancedId, "exit_set_default"]]) {
      const form = editor(page, id);
      await open(form);
      const card = form.locator('xpath=ancestor::article[contains(@class,"airport-card")][1]');
      const sibling = card.locator(`form:has(input[name="operation"][value="${operation}"])`);
      await sibling.evaluate(node => {
        for (let ancestor = node; ancestor; ancestor = ancestor.parentElement) {
          if (ancestor.tagName === "DETAILS") ancestor.open = true;
        }
      });
      await field(sibling, "password").fill("unsaved-secondary-form-password");
      await loader(form).click();
      await loaded(form);
      await field(form, "exit_name").fill(`retained-${operation}`);
      await complete(page, form);
      // Another form in this card is dirty, so the original card remains in DOM.
      assert.equal(await field(sibling, "password").inputValue(), "unsaved-secondary-form-password");
      await cleared(form);
      assert.equal(await form.locator('[name="exit_input_mode"][value="yaml"]').isChecked(), true);
      assert.equal(await field(form, "exit_proxy_yaml").isEnabled(), true);
      assert.equal(await loader(form).isEnabled(), true);
      assert.equal(await form.locator('button[type="submit"]').isEnabled(), true);
      assert.match(await form.locator("[data-exit-edit-status]").innerText(), /未载入/);
    }
    const form = editor(page);
    await loader(form).click();
    await loaded(form);
    await field(form, "password").fill(password);
    await field(form, "confirmed").check();
    await page.evaluate(() => {
      window.dispatchEvent(new PageTransitionEvent("pagehide", {persisted: true}));
      window.dispatchEvent(new PageTransitionEvent("pageshow", {persisted: true}));
    });
    await cleared(form);
    assert.equal(await form.locator('[name="exit_input_mode"][value="yaml"]').isChecked(), true);
    assert.equal(await field(form, "exit_proxy_yaml").isEnabled(), true);
    assert.equal(await loader(form).isEnabled(), true);
    assert.match(await form.locator("[data-exit-edit-status]").innerText(), /未载入/);
    await loader(form).click();
    await loaded(form);
    assert.equal(await field(form, "exit_field_password").inputValue(), secret);
    assert.deepEqual(navigations, []);
    report.checks.push(`${label}: sibling delete/default drafts preserve the card while saved editor resets; pagehide/pageshow clears secrets and allows reloading`);
  } finally { await context.close(); }
}

(async () => {
  try {
    for (const [label, engine] of [["chromium", chromium], ["webkit", webkit]]) {
      const browser = await engine.launch({headless: true});
      try {
        if (!process.argv.includes("--races-only")) {
          for (const width of [320, 390, 1440]) await directFieldsClick(browser, label, width);
          await alreadyUnlockedFieldsClick(browser, label);
          await keyboardFieldsSelection(browser, label);
          await preservedFieldsDrafts(browser, label);
          await staffFieldsClick(browser, label);
        }
        if (process.argv.includes("--fields-click-only")) {
          continue;
        }
        if (!process.argv.includes("--races-only")) {
          for (const width of [320, 390, 1440]) await editLifecycle(browser, label, width);
          await modesAndCancel(browser, label);
        }
        await delayedReveal(browser, label);
        await delayedUnlock(browser, label);
        await delayedAuthSuccess(browser, label);
        await multilineCredentials(browser, label);
        await previewDuringLoad(browser, label);
        await retainedCardAndPageHide(browser, label);
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
    console.log(`Exit-edit QA artifacts: ${directory}`);
  }
})();
