"use strict";

// Mobile rendering regression against tests/run_web_preview.py only.
// NODE_PATH=<runtime>/node_modules node tests/run_mobile_render_ui.cjs http://127.0.0.1:8795/
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {chromium, webkit} = require("playwright");

const base = new URL(process.argv[2] || "http://127.0.0.1:8795/");
if (base.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(base.hostname)
    || base.username || base.password || base.pathname !== "/" || base.search || base.hash
    || !base.port || Number(base.port) < 1024 || Number(base.port) > 65535) {
  throw new Error("Only an isolated loopback preview with an explicit unprivileged port and no query/hash is allowed.");
}
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "server-kit-mobile-render-"));
const report = {directory, checks: [], failures: [], screenshots: [], errors: [], blocked: []};
const sizes = [{width: 390, height: 844}, {width: 390, height: 600}, {width: 390, height: 430},
  {width: 320, height: 844}, {width: 320, height: 600}, {width: 320, height: 430}];
const themes = ["light", "dark", "sky"];

function check(pass, message, context, evidence = null) {
  const item = {pass: Boolean(pass), message, ...context, ...(evidence ? {evidence} : {})};
  report.checks.push(item);
  if (!pass) report.failures.push(item);
}

async function screenshot(page, name) {
  await page.screenshot({path: path.join(directory, name + ".png"), animations: "disabled"});
  report.screenshots.push(name + ".png");
}

async function pickerGeometry(page, selector, context) {
  const result = await page.locator(selector).evaluate(picker => {
    const bounds = node => {
      const r = node.getBoundingClientRect();
      return {left: r.left, top: r.top, right: r.right, bottom: r.bottom, width: r.width, height: r.height};
    };
    const group = picker.querySelector(".theme-options");
    const style = getComputedStyle(group);
    return {picker: bounds(picker), group: bounds(group), groupCss: {height: style.height, paddingTop: style.paddingTop, paddingBottom: style.paddingBottom},
      options: [...picker.querySelectorAll(".theme-option")].map(button => ({theme: button.dataset.themeValue,
        pressed: button.getAttribute("aria-pressed"), bounds: bounds(button)})),
      viewport: {width: innerWidth, height: innerHeight}, documentWidth: document.documentElement.scrollWidth};
  });
  check(result.documentWidth <= result.viewport.width + 1, "page has no horizontal overflow", context, result);
  check(result.picker.left >= -0.5 && result.picker.right <= result.viewport.width + 0.5,
    "theme picker stays inside viewport width", context, result);
  const selected = result.options.filter(item => item.pressed === "true");
  check(selected.length === 1 && selected[0].theme === context.theme, "exactly the requested theme is selected", context, result);
  for (const option of result.options) {
    const r = option.bounds, g = result.group;
    check(r.left >= g.left - 0.5 && r.right <= g.right + 0.5 && r.top >= g.top - 0.5 && r.bottom <= g.bottom + 0.5,
      `theme button ${option.theme} stays inside segmented-control border`, context, {group: g, button: r, css: result.groupCss});
    check(r.height >= 44 - 0.5, `theme button ${option.theme} has a 44px mobile target`, context, {button: r});
  }
  check(await page.locator("html").getAttribute("data-theme") === context.theme, "theme change updates root theme", context);
}

async function reachable(control, context, message) {
  await control.evaluate(node => node.scrollIntoView({block: "center", inline: "nearest"}));
  const result = await control.evaluate(node => {
    const r = node.getBoundingClientRect();
    const x = r.left + r.width / 2, y = r.top + r.height / 2;
    const hit = document.elementFromPoint(x, y);
    const panel = node.closest(".mobile-menu-panel");
    const p = panel?.getBoundingClientRect();
    return {label: node.textContent.trim() || node.getAttribute("name") || node.tagName,
      bounds: {left: r.left, top: r.top, right: r.right, bottom: r.bottom, width: r.width, height: r.height},
      insideViewport: r.left >= -0.5 && r.right <= innerWidth + 0.5 && r.top >= -0.5 && r.bottom <= innerHeight + 0.5,
      insidePanel: !p || (r.top >= p.top - 0.5 && r.bottom <= p.bottom + 0.5),
      receivesPointer: hit === node || node.contains(hit), scrollTop: panel?.scrollTop};
  });
  check(result.insideViewport && result.insidePanel && result.receivesPointer, message, context, result);
}

async function navGeometry(page, context) {
  const result = await page.locator(".mobile-nav").evaluate(nav => {
    const bounds = node => {
      const r = node.getBoundingClientRect();
      return {left: r.left, top: r.top, right: r.right, bottom: r.bottom, width: r.width, height: r.height};
    };
    return {nav: bounds(nav), items: [...nav.querySelectorAll(":scope > .nav-item, :scope > .mobile-menu > summary")].map(bounds),
      viewport: {width: innerWidth, height: innerHeight}};
  });
  check(result.items.length === 4, "bottom navigation has four slots", context, result);
  check(result.nav.left >= -0.5 && result.nav.right <= result.viewport.width + 0.5 && result.nav.bottom <= result.viewport.height + 0.5,
    "bottom navigation stays inside viewport", context, result);
  result.items.forEach((item, index) => {
    check(item.left >= result.nav.left - 0.5 && item.right <= result.nav.right + 0.5
      && item.top >= result.nav.top - 0.5 && item.bottom <= result.nav.bottom + 0.5,
    `navigation item ${index + 1} stays inside navigation`, context, result);
    if (index) check(result.items[index - 1].right <= item.left + 0.5,
      `navigation items ${index} and ${index + 1} do not overlap`, context, result);
  });
  return result;
}

async function menuCase(page, context) {
  const menu = page.locator("[data-mobile-menu]");
  const summary = menu.locator(":scope > summary");
  const before = await navGeometry(page, {...context, phase: "closed-before"});
  if (!(await menu.evaluate(node => node.open))) await summary.click();
  const button = page.locator(`.mobile-theme-picker [data-theme-value="${context.theme}"]`);
  await button.click();
  check(await menu.evaluate(node => node.open), "theme selection does not accidentally close More", context);
  const activeBackgrounds = await page.evaluate(() => {
    const current = document.querySelector(".mobile-nav > .nav-item.active");
    const more = document.querySelector(".mobile-menu[open] > summary:not(.active)");
    return {current: current ? getComputedStyle(current).backgroundColor : null,
      openMore: more ? getComputedStyle(more).backgroundColor : null};
  });
  check(activeBackgrounds.current && activeBackgrounds.openMore && activeBackgrounds.current !== activeBackgrounds.openMore,
    "current-page highlight differs from the opened More-menu highlight", context, activeBackgrounds);
  await pickerGeometry(page, ".mobile-theme-picker", context);
  const panel = page.locator(".mobile-menu-panel");
  const geometry = await panel.evaluate(node => {
    const r = node.getBoundingClientRect(), nav = document.querySelector(".mobile-nav").getBoundingClientRect();
    return {top: r.top, bottom: r.bottom, left: r.left, right: r.right, height: r.height,
      navTop: nav.top, viewportHeight: innerHeight, clientHeight: node.clientHeight, scrollHeight: node.scrollHeight,
      overflowY: getComputedStyle(node).overflowY};
  });
  check(geometry.top >= -0.5 && geometry.bottom <= geometry.navTop + 0.5,
    "More panel stays above navigation and inside short viewport", context, geometry);
  check(geometry.scrollHeight <= geometry.clientHeight + 1 || ["auto", "scroll"].includes(geometry.overflowY),
    "oversized More panel has a scrollable content area", context, geometry);
  for (const control of await panel.locator("a[href],button").all()) {
    if (await control.isVisible()) await reachable(control, context, "every More-menu control can be scrolled into view and reached");
  }
  await button.evaluate(node => node.scrollIntoView({block: "center"}));
  await screenshot(page, `${context.browser}-${context.width}x${context.height}-${context.theme}-more${context.username ? "-long-username" : ""}`);
  await page.keyboard.press("Escape");
  check(!(await menu.evaluate(node => node.open)), "Escape closes More", context);
  check(await summary.evaluate(node => node === document.activeElement), "Escape restores focus to More", context);
  const after = await navGeometry(page, {...context, phase: "closed-after"});
  check(Math.abs(before.nav.top - after.nav.top) <= 0.5 && Math.abs(before.nav.height - after.nav.height) <= 0.5,
    "theme changes and menu close do not shift bottom-navigation geometry", context, {before: before.nav, after: after.nav});
  await summary.click();
  await panel.locator("[data-mobile-menu-close]").click();
  check(!(await menu.evaluate(node => node.open)), "close button remains reachable on short screens", context);
  await summary.click();
  await page.mouse.click(2, 2);
  check(!(await menu.evaluate(node => node.open)), "outside click closes More", context);
}

async function loginCase(page, context) {
  const button = page.locator(`.login-theme-picker [data-theme-value="${context.theme}"]`);
  await button.click();
  await pickerGeometry(page, ".login-theme-picker", context);
  for (const selector of ['[name="username"]', '[name="password"]', 'button[type="submit"]']) {
    await reachable(page.locator(selector), context, "login fields and submit remain reachable below the theme picker");
  }
  // The fixed picker must not cover either field when the form is brought into view.
  const overlap = await page.locator(".login-theme-picker").evaluate(picker => {
    const p = picker.getBoundingClientRect();
    return [...document.querySelectorAll('.login-card input:not([type="hidden"]), .login-card button[type="submit"]')].map(field => {
      const r = field.getBoundingClientRect();
      return {field: field.name || "submit", visible: r.bottom > 0 && r.top < innerHeight,
        overlap: Math.max(0, Math.min(p.right, r.right) - Math.max(p.left, r.left))
          * Math.max(0, Math.min(p.bottom, r.bottom) - Math.max(p.top, r.top))};
    });
  });
  check(overlap.every(item => !item.visible || item.overlap < 0.5), "login theme picker does not overlap visible form controls", context, overlap);
  if (overlap.some(item => item.visible && item.overlap >= 0.5)) {
    await screenshot(page, `${context.browser}-${context.width}x${context.height}-${context.theme}-login-overlap`);
  }
  await page.evaluate(() => window.scrollTo(0, 0));
  await screenshot(page, `${context.browser}-${context.width}x${context.height}-${context.theme}-login`);
}

async function localActionTargets(page, context) {
  const pages = [
    {path: "network/nodes/", name: "nodes", selectors: [".node-exit-form > .copy-button"]},
    {path: "network/subscriptions/", name: "domains", selectors: [".public-endpoint-actions button", ".duckdns-token-form button"]},
    {path: "backups/", name: "backups", selectors: [".backup-actions .secondary-button", ".backup-actions .copy-button"]},
  ];
  for (const item of pages) {
    await page.goto(new URL(item.path, base).href);
    await page.evaluate(() => {
      document.querySelectorAll(".node-exit-form, .public-endpoint-actions, .backup-actions").forEach(node => {
        for (let parent = node; parent; parent = parent.parentElement) if (parent.tagName === "DETAILS") parent.open = true;
      });
    });
    if (item.name === "domains") await page.locator("[data-dynamic-dns-provider]").selectOption("dnspod");
    for (const theme of themes) {
      const menu = page.locator("[data-mobile-menu]");
      await menu.locator(":scope > summary").click();
      await page.locator(`.mobile-theme-picker [data-theme-value="${theme}"]`).click();
      await page.keyboard.press("Escape");
      for (const selector of item.selectors) {
        const controls = page.locator(selector);
        check(await controls.count() > 0, "expected legacy action controls are present", {...context, theme, page: item.name, selector});
        for (const control of await controls.all()) {
          if (!(await control.isVisible())) continue;
          const bounds = await control.boundingBox();
          check(bounds.height >= 43.5, "legacy-specific button rules do not override the 44px mobile minimum",
            {...context, theme, page: item.name, selector}, {label: await control.innerText(), bounds});
          await reachable(control, {...context, theme, page: item.name, selector}, "local action buttons remain reachable above bottom navigation");
        }
      }
      check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1),
        "legacy action page has no horizontal overflow", {...context, theme, page: item.name});
      if (theme === "light") await screenshot(page, `${context.browser}-${context.width}x${context.height}-${item.name}-actions`);
    }
  }
}

(async () => {
  try {
    for (const [name, engine] of [["chromium", chromium], ["webkit", webkit]]) {
      const browser = await engine.launch({headless: true});
      const context = await browser.newContext({viewport: sizes[0], isMobile: true, hasTouch: true});
      await context.route("**/*", route => {
        if (new URL(route.request().url()).origin === base.origin) return route.continue();
        report.blocked.push(route.request().url());
        return route.abort();
      });
      const page = await context.newPage();
      page.setDefaultTimeout(6000);
      page.on("pageerror", error => report.errors.push(error.message));
      try {
        await page.goto(new URL("login/", base).href);
        for (const size of sizes) {
          await page.setViewportSize(size);
          for (const theme of themes) await loginCase(page, {browser: name, ...size, theme, page: "login"});
        }
        await page.setViewportSize(sizes[0]);
        await page.locator('[name="username"]').fill("preview");
        await page.locator('[name="password"]').fill("Preview-only-2026!");
        await Promise.all([page.waitForURL(base.href), page.locator('button[type="submit"]').click()]);
        const preview = await page.goto(new URL("__preview__/", base).href);
        const previewHeading = await page.locator("h1").innerText();
        if (preview.status() !== 200 || !previewHeading.includes("本地视觉审查") || !previewHeading.includes("合成数据")
            || !(await page.locator("body").innerText()).includes("仅本机临时环境")) {
          throw new Error("The server did not identify itself as the isolated synthetic-data preview.");
        }
        check(true, "server explicitly identifies as a local synthetic-data preview", {browser: name});
        await page.goto(base.href);
        for (const size of sizes) {
          await page.setViewportSize(size);
          for (const theme of themes) await menuCase(page, {browser: name, ...size, theme, page: "dashboard"});
        }
        await page.setViewportSize({width: 320, height: 430});
        await page.locator(".mobile-logout > span").evaluate(node => {
          node.textContent = "synthetic-administrator-with-a-very-long-unbroken-name-for-layout-testing";
        });
        for (const theme of themes) await menuCase(page, {browser: name, width: 320, height: 430, theme,
          page: "dashboard", username: "synthetic-long"});
        for (const width of [390, 320]) {
          const size = {width, height: 430};
          await page.setViewportSize(size);
          await localActionTargets(page, {browser: name, ...size});
        }
      } finally { await browser.close(); }
    }
    check(report.errors.length === 0, "no browser script errors", {}, report.errors);
    check(report.blocked.length === 0, "no external resource requests", {}, report.blocked);
    if (report.failures.length) process.exitCode = 1;
  } catch (error) {
    report.fatal = error.stack;
    process.exitCode = 1;
    console.error(error.stack);
  } finally {
    fs.writeFileSync(path.join(directory, "report.json"), JSON.stringify(report, null, 2));
    console.log(JSON.stringify({directory, checks: report.checks.length, failures: report.failures.length,
      screenshots: report.screenshots.length, errors: report.errors, blocked: report.blocked,
      firstFailures: report.failures.slice(0, 8)}, null, 2));
  }
})();
