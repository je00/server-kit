"use strict";

// Run against tests/run_web_preview.py only. Account mutations affect its
// disposable SQLite database; external requests and non-loopback URLs fail closed.
const {chromium, webkit} = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

async function main() {
  const base = new URL(process.argv[2] || "http://127.0.0.1:8765/");
  if (base.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(base.hostname)
      || base.username || base.password || base.pathname !== "/" || base.search || base.hash
      || !base.port || Number(base.port) < 1024) {
    throw new Error("Use an isolated http://127.0.0.1:PORT/ preview, never a production host.");
  }
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "server-kit-accounts-ui-"));
  const results = [];
  for (const [name, engine] of [["chromium", chromium], ["webkit", webkit]]) {
    const browser = await engine.launch({headless: true});
    try {
      const context = await browser.newContext({viewport: {width: 390, height: 844}});
      const blocked = [];
      await context.route("**/*", route => {
        if (new URL(route.request().url()).origin === base.origin) return route.continue();
        blocked.push(route.request().url());
        return route.abort();
      });
      const page = await context.newPage();
      const errors = [];
      page.on("pageerror", error => errors.push(String(error)));
      await page.goto(new URL("login/", base).href);
      await page.locator('[name="username"]').fill("preview");
      await page.locator('[name="password"]').fill("Preview-only-2026!");
      await Promise.all([page.waitForURL(base.href), page.locator('button[type="submit"]').click()]);
      await page.goto(new URL("__preview__/", base).href);
      assert.equal(await page.title(), "Local visual preview", "Refuse account changes without the preview-only index.");
      assert.match(await page.locator("h1").textContent(), /合成数据/);
      await page.goto(new URL("accounts/", base).href);
      let navigations = 0;
      let posts = 0;
      page.on("framenavigated", frame => { if (frame === page.mainFrame()) navigations += 1; });
      page.on("request", request => {
        if (request.method() === "POST" && request.url() === new URL("accounts/", base).href) posts += 1;
      });
      const username = `review-${name}-${Date.now()}`;
      const other = page.locator("[data-account-card]").filter({
        has: page.locator("[data-account-name]", {hasText: "administrator-with-long-name"}),
      });
      await other.locator("summary").filter({hasText: "重置密码"}).click();
      await other.locator('[name="new_password"]').fill("unsent-other-account-password");
      const form = page.locator(".account-create-form");
      await form.locator('[name="username"]').fill(username);
      await form.locator('[name="role"]').selectOption("viewer");
      await form.locator('[name="new_password"]').fill("unique-accounts-review-password");
      await form.locator('[name="current_password"]').fill("wrong-password");
      await form.locator('[name="confirmed"]').check();
      await form.locator('button[type="submit"]').click();
      await form.locator("[data-account-feedback].danger").waitFor({state: "visible"});
      assert.equal(await form.locator('[name="username"]').inputValue(), username);
      assert.equal(await form.locator('[name="role"]').inputValue(), "viewer");
      assert.equal(await form.locator('[name="new_password"]').inputValue(), "unique-accounts-review-password");
      assert.equal(await other.locator('[name="new_password"]').inputValue(), "unsent-other-account-password");

      async function capture(width, label) {
        await page.setViewportSize({width, height: width < 768 ? 844 : 1000});
        await page.evaluate(() => { document.activeElement?.blur(); window.scrollTo(0, 0); });
        const metrics = await page.evaluate(() => {
          const visible = element => element.getClientRects().length > 0;
          const forms = [...document.querySelectorAll(".account-actions details[open] form")];
          const buttons = [...document.querySelectorAll("main button, main summary.copy-button")].filter(visible);
          const rows = [...document.querySelectorAll("[data-account-list] > article")];
          return {
            overflow: document.documentElement.scrollWidth > innerWidth + 1,
            minButtonHeight: Math.min(...buttons.map(button => button.getBoundingClientRect().height)),
            escapingForms: forms.filter(form => {
              const rect = form.getBoundingClientRect();
              const row = form.closest("article").getBoundingClientRect();
              return rect.left < row.left - 1 || rect.right > row.right + 1 || rect.bottom > row.bottom + 1;
            }).length,
            overlappingRows: rows.filter((row, index) => index > 0
              && row.getBoundingClientRect().top < rows[index - 1].getBoundingClientRect().bottom - 1).length,
          };
        });
        assert.equal(metrics.overflow, false, `${name}/${width}: horizontal overflow`);
        assert.equal(metrics.escapingForms, 0, `${name}/${width}: expanded form escaped its row`);
        assert.equal(metrics.overlappingRows, 0, `${name}/${width}: overlapping identity rows`);
        if (width < 768) assert.ok(metrics.minButtonHeight >= 43.9, `${name}/${width}: touch target < 44px`);
        await page.screenshot({path: path.join(directory, `${name}-${width}-${label}.png`), fullPage: true});
        return {width, label, ...metrics};
      }
      const layout = [await capture(390, "error")];
      await form.locator('[name="current_password"]').fill("Preview-only-2026!");
      const beforePosts = posts;
      await form.evaluate(element => {
        element.dispatchEvent(new Event("submit", {bubbles: true, cancelable: true}));
        element.dispatchEvent(new Event("submit", {bubbles: true, cancelable: true}));
      });
      const card = page.locator("[data-account-card]").filter({has: page.locator("[data-account-name]", {hasText: username})});
      await card.waitFor();
      await form.locator("[data-account-feedback].success").waitFor({state: "visible"});
      assert.equal(posts - beforePosts, 1, "Double submit must send one mutation request.");
      assert.equal(await form.locator('[name="new_password"]').inputValue(), "");
      assert.equal(await form.locator('[name="current_password"]').inputValue(), "");
      assert.equal(await other.locator('[name="new_password"]').inputValue(), "unsent-other-account-password");
      await card.locator("[data-account-toggle-label]").click();
      await card.locator('[data-account-toggle] [name="current_password"]').fill("Preview-only-2026!");
      await card.locator("[data-account-toggle-confirm]").click();
      await card.locator("[data-account-feedback].success").waitFor({state: "visible"});
      assert.equal(await card.locator("[data-account-toggle-confirm]").textContent(), "确认启用");
      assert.equal(await card.locator('[data-account-toggle] [name="current_password"]').inputValue(), "");
      assert.equal(navigations, 0);
      layout.push(await capture(390, "success"), await capture(1440, "success"));
      assert.deepEqual(errors, []);
      assert.deepEqual(blocked, []);
      results.push({engine: name, navigations, posts, errors, blocked, layout});
    } finally {
      await browser.close();
    }
  }
  fs.writeFileSync(path.join(directory, "report.json"), JSON.stringify(results, null, 2));
  console.log(JSON.stringify({directory, results}, null, 2));
}

main().catch(error => { console.error(error); process.exitCode = 1; });
