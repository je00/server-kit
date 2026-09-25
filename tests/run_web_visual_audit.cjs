"use strict";

// Optional browser QA. Requires Playwright + a Chromium browser installation.
// Run the isolated preview first; this script refuses non-loopback origins.
const {chromium} = require("playwright");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

async function main() {
  const base = new URL(process.argv[2] || "http://127.0.0.1:8765/");
  if (base.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(base.hostname)
    || base.username || base.password || base.pathname !== "/") {
    throw new Error("Use an isolated http://127.0.0.1:PORT/ preview, never a production host.");
  }
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "server-kit-visual-audit-"));
  const browser = await chromium.launch({headless: true});
  const context = await browser.newContext({viewport: {width: 1440, height: 1000}});
  const blocked = [];
  await context.route("**/*", route => {
    if (new URL(route.request().url()).origin === base.origin) return route.continue();
    blocked.push(route.request().url());
    return route.abort();
  });
  const page = await context.newPage();
  const errors = [];
  const checks = [];
  page.on("pageerror", error => errors.push(error.message));
  try {
    await page.goto(new URL("login/", base).href);
    await page.screenshot({path: path.join(directory, "login-desktop.png"), fullPage: true});
    await page.locator('[name="username"]').fill("preview");
    await page.locator('[name="password"]').fill("Preview-only-2026!");
    await Promise.all([page.waitForURL(base.href), page.locator('button[type="submit"]').click()]);
    await page.goto(new URL("__preview__/", base).href);
    const routes = await page.locator('a[href^="/"]').evaluateAll(links => [...new Set(links
      .map(link => link.getAttribute("href"))
      .filter(href => !href.startsWith("/__preview__/scenario/")))]);
    if (routes.length < 30) throw new Error("Expected the complete preview-only route inventory.");
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({width, height: width >= 768 ? 1000 : 844});
      for (const route of routes) {
        const response = await page.goto(new URL(route, base).href);
        await page.evaluate(() => document.activeElement?.blur());
        const metrics = await page.evaluate(() => ({
          horizontalOverflow: document.documentElement.scrollWidth > window.innerWidth + 1,
          mainCount: document.querySelectorAll("main#main-content").length,
          titleCount: document.querySelectorAll("main h1").length,
        }));
        const name = route === "/" ? "overview" : route.replace(/[^a-zA-Z0-9-]+/g, "-").replace(/^-|-$/g, "");
        await page.screenshot({path: path.join(directory, `${width}-${name}.png`), fullPage: true});
        checks.push({route, width, status: response.status(), ...metrics});
      }
    }
    const failures = checks.filter(check => check.status !== 200 || check.horizontalOverflow
      || check.mainCount !== 1 || check.titleCount !== 1);
    const report = {base: base.origin, checks, failures, errors, blocked};
    fs.writeFileSync(path.join(directory, "report.json"), JSON.stringify(report, null, 2));
    console.log(JSON.stringify({directory, pages: routes.length, screenshots: checks.length + 1,
      layoutFailures: failures.length, scriptErrors: errors.length, externalRequests: blocked.length}, null, 2));
    if (failures.length || errors.length || blocked.length) process.exitCode = 1;
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
