"use strict";

// A deliberately small, offline DOM fixture. It is not a layout engine: real
// screenshots and viewport overflow checks belong to the local visual review.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const bundleKey = "server-kit-awg-generated-bundle-v1";

function makeBrowser({blockedStorage = false, stored = {}} = {}) {
  const memory = new Map(Object.entries(stored));
  const timers = new Map();
  let clock = 1000;
  let sequence = 0;
  const eventHandlers = new Map();
  let document;

  function element(tag = "div") {
    const handlers = new Map();
    const attributes = new Map();
    const classes = new Set();
    return {
      tagName: tag.toUpperCase(), dataset: {}, style: {}, children: [], queries: new Map(),
      textContent: "", value: "", hidden: false, disabled: false, isConnected: true,
      parentElement: null, tabIndex: 0, elements: {},
      classList: {
        add: (...names) => names.forEach(name => classes.add(name)),
        remove: (...names) => names.forEach(name => classes.delete(name)),
        contains: name => classes.has(name),
        toggle(name, value) {
          const selected = value === undefined ? !classes.has(name) : value;
          if (selected) classes.add(name); else classes.delete(name);
          return selected;
        },
      },
      addEventListener(type, listener) {
        if (!handlers.has(type)) handlers.set(type, []);
        handlers.get(type).push(listener);
      },
      dispatch(type, extra = {}) {
        const event = {target: this, currentTarget: this, defaultPrevented: false,
          preventDefault() { this.defaultPrevented = true; }, ...extra};
        for (const handler of handlers.get(type) || []) handler(event);
        return event;
      },
      setAttribute(name, value) { attributes.set(name, String(value)); },
      getAttribute(name) { return attributes.get(name) ?? null; },
      hasAttribute(name) { return attributes.has(name); },
      removeAttribute(name) { attributes.delete(name); },
      append(...items) { items.forEach(item => { item.parentElement = this; }); this.children.push(...items); },
      appendChild(item) { this.append(item); return item; },
      replaceChildren(...items) { this.children = []; this.append(...items); },
      get childNodes() { return this.children; },
      querySelector(selector) { return this.querySelectorAll(selector)[0] || null; },
      querySelectorAll(selector) {
        if (this.queries.has(selector)) return this.queries.get(selector);
        if (selector.includes("button") && selector.includes("input")) return this.focusables || [];
        return [];
      },
      closest(selector) {
        if (selector === "[hidden]" && this.hidden) return this;
        if (this.selectors?.includes(selector)) return this;
        return this.parentElement?.closest(selector) || null;
      },
      matches(selector) { return this.selectors?.includes(selector) || false; },
      contains(item) { return item === this || this.children.some(child => child.contains(item)); },
      focus() { document.activeElement = this; },
      click() { this.dispatch("click"); },
      remove() { this.isConnected = false; },
      getClientRects() { return this.hidden ? [] : [{width: 40, height: 40}]; },
      scrollIntoView() {}, select() {}, reset() {},
    };
  }

  const storage = {
    getItem(key) { if (blockedStorage) throw new Error("Storage disabled"); return memory.get(key) || null; },
    setItem(key, value) { if (blockedStorage) throw new Error("Storage disabled"); memory.set(key, String(value)); },
    removeItem(key) { if (blockedStorage) throw new Error("Storage disabled"); memory.delete(key); },
  };
  document = element("document");
  document.body = element("body");
  document.documentElement = element("html");
  document.activeElement = document.body;
  document.createElement = element;
  document.getElementById = () => null;
  document.readyState = "complete";
  document.visibilityState = "visible";
  document.hidden = false;

  const window = {
    document, sessionStorage: storage, localStorage: storage,
    navigator: {userAgent: "Offline browser fixture"},
    location: {href: "http://127.0.0.1:9080/", hash: "", reload() { throw new Error("Unexpected reload"); }},
    history: {replaceState() {}},
    matchMedia: () => ({matches: false, addEventListener() {}}),
    getSelection: () => ({toString: () => ""}),
    getComputedStyle: () => ({display: "block", visibility: "visible"}),
    addEventListener(type, listener) {
      if (!eventHandlers.has(type)) eventHandlers.set(type, []);
      eventHandlers.get(type).push(listener);
    },
    setTimeout(callback, delay = 0) {
      const id = ++sequence; timers.set(id, {callback, at: clock + delay, repeat: 0}); return id;
    },
    clearTimeout: id => timers.delete(id),
    setInterval(callback, delay) {
      const id = ++sequence; timers.set(id, {callback, at: clock + delay, repeat: delay}); return id;
    },
    clearInterval: id => timers.delete(id),
  };
  class FixtureDate extends Date { static now() { return clock; } }
  const context = vm.createContext({window, document, navigator: window.navigator, URL,
    Date: FixtureDate, console, Element: Object, HTMLElement: Object,
    getComputedStyle: window.getComputedStyle,
    setTimeout: window.setTimeout, clearTimeout: window.clearTimeout,
    setInterval: window.setInterval, clearInterval: window.clearInterval,
    fetch: () => { throw new Error("Network access is forbidden in these tests"); }});

  return {
    context, document, window, memory, element,
    load(file) { vm.runInContext(fs.readFileSync(path.join(root, "web/static", file), "utf8"), context); },
    call(source) { return vm.runInContext(source, context); },
    dispatchWindow(type) { for (const handler of eventHandlers.get(type) || []) handler({type}); },
    advance(milliseconds) {
      const end = clock + milliseconds;
      for (let safety = 0; safety < 10000; safety += 1) {
        const due = [...timers.entries()].filter(([, timer]) => timer.at <= end)
          .sort((left, right) => left[1].at - right[1].at)[0];
        if (!due) { clock = end; return; }
        const [id, timer] = due;
        clock = timer.at;
        timers.delete(id);
        if (timer.repeat) timers.set(id, {...timer, at: clock + timer.repeat});
        timer.callback();
      }
      throw new Error("Timer loop exceeded fixture limit");
    },
  };
}

function fixtureBundle(expiresAt = 1200) {
  return {name: "demo-laptop", address: "10.20.0.23", expiresAt,
    enrollmentToken: "FAKE-ENROLLMENT-TOKEN",
    profiles: [{fileName: "demo-main.conf", label: "主入口", profile: "main", config: "FAKE-PRIVATE-CONFIG"}]};
}

function makeTaskBrowser() {
  const browser = makeBrowser();
  function taskContent(label) {
    const main = browser.element("main");
    const status = browser.element("span");
    const toggle = browser.element("button");
    const content = browser.element("section");
    main.setAttribute("data-task-refresh", "true");
    status.selectors = ["[data-task-refresh-status]"];
    toggle.selectors = ["[data-task-refresh-toggle]"];
    content.textContent = label;
    main.append(status, toggle, content);
    main.queries.set("[data-task-refresh-status]", [status]);
    main.queries.set("[data-task-refresh-toggle]", [toggle]);
    const replaceChildren = main.replaceChildren.bind(main);
    main.replaceChildren = (...items) => {
      replaceChildren(...items);
      for (const selector of ["[data-task-refresh-status]", "[data-task-refresh-toggle]"]) {
        main.queries.set(selector, items.filter(item => item.matches(selector)));
      }
    };
    return {main, status, toggle, content};
  }
  const current = taskContent("ORIGINAL TASK CONTENT");
  let next = taskContent("UPDATED TASK CONTENT");
  browser.document.body.append(current.main);
  browser.document.queries.set("[data-task-live][data-task-refresh]", [current.main]);
  browser.document.queries.set("[data-task-refresh]", [current.main]);
  browser.document.queries.set("[data-task-refresh-status]", [current.status]);
  const requests = [];
  let responder = async () => ({ok: true, redirected: false, text: async () => "fixture"});
  browser.context.AbortController = AbortController;
  browser.context.DOMParser = class {
    parseFromString() { return {querySelector: () => next.main, title: "Updated fixture task"}; }
  };
  browser.context.fetch = (...args) => { requests.push(args); return responder(...args); };
  browser.load("app.js");
  return {...browser, current, requests,
    setResponder(value) { responder = value; },
    setNext(value) { next = taskContent(value); },
    next: () => next,
    async poll() { await browser.call("refreshTaskContent()"); },
    async flush() { for (let index = 0; index < 8; index += 1) await Promise.resolve(); },
  };
}

const cases = {
  "theme-storage-disabled"() {
    const browser = makeBrowser({blockedStorage: true});
    const button = browser.element("button");
    button.dataset.themeValue = "dark";
    button.selectors = ["[data-theme-value]"];
    browser.document.queries.set("[data-theme-value]", [button]);
    browser.load("theme.js");
    assert.equal(browser.document.documentElement.dataset.theme, "light");
    browser.document.dispatch("click", {target: button});
    assert.equal(browser.document.documentElement.dataset.theme, "dark");
    assert.equal(button.getAttribute("aria-pressed"), "true");
  },
  "theme-restore"() {
    for (const [saved, expected] of [["sky", "sky"], ["light", "light"], ["dark", "dark"], ["unexpected", "light"]]) {
      const browser = makeBrowser({stored: {"server-kit-theme": saved}});
      browser.load("theme.js");
      assert.equal(browser.document.documentElement.dataset.theme, expected);
    }
  },
  "bundle-storage-disabled"() {
    const browser = makeBrowser({blockedStorage: true});
    browser.load("app.js");
    assert.equal(browser.call("readGeneratedBundle()"), null);
    assert.doesNotThrow(() => browser.call("saveGeneratedBundle({expiresAt: 2000})"));
    assert.doesNotThrow(() => browser.call(`safeRemoveSessionItem(${JSON.stringify(bundleKey)})`));
  },
  "bundle-expired"() {
    const browser = makeBrowser({stored: {[bundleKey]: JSON.stringify(fixtureBundle(900))}});
    browser.load("app.js");
    assert.equal(browser.call("readGeneratedBundle()"), null);
    assert.equal(browser.memory.has(bundleKey), false);
  },
  "bundle-malformed"() {
    for (const value of ["{invalid", "null", JSON.stringify({expiresAt: 2000}),
      JSON.stringify({...fixtureBundle(), profiles: "invalid"})]) {
      const browser = makeBrowser({stored: {[bundleKey]: value}});
      browser.load("app.js");
      assert.equal(browser.call("readGeneratedBundle()"), null);
      assert.equal(browser.memory.has(bundleKey), false);
    }
  },
  "bundle-live-expiration"() {
    const browser = makeBrowser({stored: {[bundleKey]: JSON.stringify(fixtureBundle())}});
    const generator = browser.element("section");
    const fields = new Map();
    for (const name of ["form", "context", "result", "profile-list", "enrollment-token", "enrollment-form", "reset", "status"]) {
      const field = browser.element(name.includes("form") ? "form" : "div");
      fields.set(name, field);
      const selector = name === "profile-list" ? "[data-awg-profile-list]"
        : name.startsWith("enrollment") ? `[data-awg-${name}]` : `[data-awg-generator-${name}]`;
      generator.queries.set(selector, [field]);
    }
    browser.document.queries.set("[data-awg-generator]", [generator]);
    browser.load("app.js");
    assert.equal(fields.get("form").hidden, true);
    assert.equal(fields.get("enrollment-token").value, "FAKE-ENROLLMENT-TOKEN");
    browser.advance(1000);
    assert.equal(browser.memory.has(bundleKey), false, "Expired keys remain in session storage");
    assert.equal(fields.get("profile-list").children.length, 0, "Expired profile actions remain in the DOM");
    assert.equal(fields.get("enrollment-token").value, "", "Expired enrollment token remains in the DOM");
    assert.equal(fields.get("result").hidden, true);
    assert.equal(fields.get("form").hidden, false);
  },
  "modal-focus"() {
    const browser = makeBrowser();
    const opener = browser.element("button");
    const modal = browser.element("div");
    const dialog = browser.element("section");
    const first = browser.element("button");
    const last = browser.element("input");
    modal.hidden = true;
    modal.selectors = [".qr-modal", "[data-qr-modal]"];
    modal.focusables = [first, last];
    dialog.focusables = [first, last];
    dialog.append(first, last);
    modal.append(dialog);
    modal.queries.set('[role="dialog"]', [dialog]);
    browser.document.body.append(opener, modal);
    browser.document.queries.set(".qr-modal:not([hidden])", [modal]);
    browser.context.testModal = modal;
    browser.context.testOpener = opener;
    opener.focus();
    browser.load("app.js");
    browser.call("openManagedModal(testModal, testOpener)");
    assert.equal(modal.hidden, false);
    last.focus();
    const forward = browser.document.dispatch("keydown", {key: "Tab", target: last, shiftKey: false});
    assert.equal(forward.defaultPrevented, true);
    assert.equal(browser.document.activeElement, first);
    const reverse = browser.document.dispatch("keydown", {key: "Tab", target: first, shiftKey: true});
    assert.equal(reverse.defaultPrevented, true);
    assert.equal(browser.document.activeElement, last);
    browser.call("closeManagedModal(testModal)");
    assert.equal(modal.hidden, true);
    assert.equal(browser.document.activeElement, opener);
  },
  "modal-secret-cleanup"() {
    const browser = makeBrowser();
    const qr = browser.element("div");
    const image = browser.element("img");
    const secret = browser.element("div");
    const value = browser.element("pre");
    image.setAttribute("src", "data:image/png;base64,FAKE-SECRET-QR");
    image.alt = "Fake secret QR";
    value.textContent = "FAKE-PRIVATE-CONFIG";
    qr.queries.set("[data-qr-image]", [image]);
    secret.queries.set("[data-secret-value]", [value]);
    browser.document.queries.set("[data-qr-modal]", [qr]);
    browser.document.queries.set("[data-secret-modal]", [secret]);
    browser.load("app.js");
    browser.call("closeQrModal(); closeSecretModal();");
    assert.equal(qr.hidden, true);
    assert.equal(image.getAttribute("src"), null);
    assert.equal(image.alt, "");
    assert.equal(secret.hidden, true);
    assert.equal(value.textContent, "");
    assert.doesNotThrow(() => browser.call("closeQrModal(); closeSecretModal();"));
  },
  "form-submit-payload"() {
    const browser = makeBrowser();
    const form = browser.element("form");
    const button = browser.element("button");
    form.method = "post";
    form.action = "/backups/";
    button.name = "operation";
    button.value = "preview_restore";
    button.textContent = "恢复预览";
    browser.load("app.js");
    const first = browser.document.dispatch("submit", {target: form, submitter: button});
    assert.equal(first.defaultPrevented, false);
    assert.equal(button.disabled, false, "Disabled submitter drops its operation from the real browser POST");
    assert.equal(button.name, "operation");
    assert.equal(button.value, "preview_restore");
    assert.equal(button.getAttribute("aria-disabled"), "true");
    const duplicate = browser.document.dispatch("submit", {target: form, submitter: button});
    assert.equal(duplicate.defaultPrevented, true);
    browser.dispatchWindow("pageshow");
    assert.equal(button.textContent, "恢复预览");
    assert.equal(form.getAttribute("aria-busy"), null);
    assert.equal(browser.document.dispatch("submit", {target: form, submitter: button}).defaultPrevented, false);
  },
  "form-validation-cancelled"() {
    const browser = makeBrowser();
    const form = browser.element("form");
    const button = browser.element("button");
    form.method = "post";
    form.action = "/network/proxy/";
    browser.load("app.js");
    browser.document.dispatch("submit", {target: form, submitter: button, defaultPrevented: true});
    assert.equal(form.getAttribute("aria-busy"), null);
    assert.equal(button.getAttribute("aria-disabled"), null);
    assert.equal(browser.document.dispatch("submit", {target: form, submitter: button}).defaultPrevented, false);
  },
  "logout-clears-bundle"() {
    const browser = makeBrowser({stored: {[bundleKey]: JSON.stringify(fixtureBundle())}});
    const form = browser.element("form");
    form.method = "post";
    form.action = "/logout/";
    browser.load("app.js");
    browser.document.dispatch("submit", {target: form});
    assert.equal(browser.memory.has(bundleKey), false);
  },
  "list-filter"() {
    const browser = makeBrowser();
    const container = browser.element("section");
    const label = browser.element("label");
    const input = browser.element("input");
    const empty = browser.element("div");
    const items = ["Office-Desktop 10.20.0.12", "nas-storage", "iPhone"].map(text => {
      const item = browser.element("article"); item.dataset.filterLabel = text; return item;
    });
    label.append(input);
    container.queries.set("[data-filter-input]", [input]);
    container.queries.set("[data-filter-item]", items);
    container.queries.set("[data-filter-empty]", [empty]);
    browser.document.queries.set("[data-list-filter]", [container]);
    browser.load("app.js");
    input.value = "  OFFICE  ";
    input.dispatch("input");
    assert.deepEqual(items.map(item => item.hidden), [false, true, true]);
    assert.equal(empty.hidden, true);
    input.value = "not-present";
    input.dispatch("input");
    assert.equal(empty.hidden, false);
    assert.equal(items.every(item => item.hidden), true);
    input.dispatch("keydown", {key: "Escape"});
    assert.equal(input.value, "");
    assert.equal(items.some(item => item.hidden), false);
    assert.equal(empty.hidden, true);
  },
  async "task-poll-interval"() {
    const browser = makeTaskBrowser();
    browser.advance(4999);
    assert.equal(browser.requests.length, 0);
    browser.advance(1);
    await browser.flush();
    assert.equal(browser.requests.length, 1);
    assert.equal(browser.current.main.children[2].textContent, "UPDATED TASK CONTENT");
    assert.equal(browser.document.title, "Updated fixture task");
    assert.equal(browser.requests[0][1].cache, "no-store");
    assert.equal(browser.requests[0][1].credentials, "same-origin");
    browser.setNext("SECOND UPDATE");
    browser.advance(5000);
    await browser.flush();
    assert.equal(browser.requests.length, 2);
    assert.equal(browser.current.main.children[2].textContent, "SECOND UPDATE");
  },
  async "task-poll-pause-resume"() {
    const browser = makeTaskBrowser();
    browser.current.toggle.focus();
    browser.document.dispatch("click", {target: browser.current.toggle});
    await browser.poll();
    assert.equal(browser.requests.length, 0);
    assert.equal(browser.current.main.children[2].textContent, "ORIGINAL TASK CONTENT");
    browser.document.dispatch("click", {target: browser.current.toggle});
    await browser.poll();
    assert.equal(browser.requests.length, 1, "Focusing the resume toggle must not block resumed polling");
    assert.equal(browser.current.main.children[2].textContent, "UPDATED TASK CONTENT");
    assert.equal(browser.document.activeElement, browser.next().toggle);

    let resolve;
    browser.setResponder(() => new Promise(done => { resolve = done; }));
    const pending = browser.poll();
    browser.document.dispatch("click", {target: browser.next().toggle});
    browser.setNext("MUST NOT REPLACE WHILE PAUSED");
    resolve({ok: true, redirected: false, text: async () => "fixture"});
    await pending;
    assert.equal(browser.current.main.children[2].textContent, "UPDATED TASK CONTENT");
  },
  async "task-poll-selection"() {
    const browser = makeTaskBrowser();
    let selection = "selected task text";
    browser.window.getSelection = () => ({toString: () => selection});
    await browser.poll();
    assert.equal(browser.requests.length, 0);
    selection = "";
    let resolve;
    browser.setResponder(() => new Promise(done => { resolve = done; }));
    const pending = browser.poll();
    selection = "text selected after request began";
    resolve({ok: true, redirected: false, text: async () => "fixture"});
    await pending;
    assert.equal(browser.current.main.children[2].textContent, "ORIGINAL TASK CONTENT");
    assert.equal(selection, "text selected after request began");
  },
  async "task-poll-errors"() {
    for (const response of [{ok: false, status: 503}, {ok: true, redirected: true, status: 200}]) {
      const browser = makeTaskBrowser();
      browser.setResponder(async () => response);
      await browser.poll();
      assert.equal(browser.current.main.children[2].textContent, "ORIGINAL TASK CONTENT");
      assert.match(browser.current.status.textContent, /更新失败/);
      browser.setResponder(async () => ({ok: true, redirected: false, text: async () => "fixture"}));
      await browser.poll();
      assert.equal(browser.current.main.children[2].textContent, "UPDATED TASK CONTENT", "Failed requests must release the busy guard");
    }
  },
  "local-time"() {
    for (const timezone of ["UTC", "America/Chicago", "Asia/Shanghai"]) {
      const browser = makeBrowser();
      const time = browser.element("time");
      const invalid = browser.element("time");
      const iso = "2026-09-24T09:41:05.000Z";
      time.setAttribute("datetime", iso);
      invalid.setAttribute("datetime", "not a date");
      invalid.textContent = "Unknown";
      browser.document.queries.set("time[data-local-time][datetime]", [time, invalid]);
      browser.context.Intl = {DateTimeFormat: function (locale, options) {
        return new Intl.DateTimeFormat(locale, {...options, timeZone: timezone});
      }};
      browser.load("app.js");
      const expected = new Intl.DateTimeFormat("zh-CN", {year: "numeric", month: "2-digit", day: "2-digit",
        hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false, timeZoneName: "short", timeZone: timezone}).format(new Date(iso));
      assert.equal(time.textContent, expected);
      assert.equal(time.title, `原始时间：${iso}`);
      assert.equal(time.getAttribute("datetime"), iso);
      assert.equal(invalid.textContent, "Unknown");
    }
  },
};

const name = process.argv[2];
assert.ok(Object.hasOwn(cases, name), `Unknown UI contract: ${name}`);
Promise.resolve(cases[name]()).then(() => console.log(`PASS ${name}`)).catch(error => {
  console.error(error);
  process.exitCode = 1;
});
