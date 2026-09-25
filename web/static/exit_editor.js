"use strict";

// Secrets are loaded only by the existing password-unlocked endpoint. Keep
// drafts in this form, never storage; retain opaque advanced proxy options.
const exitEditorStates = new WeakMap();
const exitEditorFieldNames = ["server", "port", "username", "password"];
const exitField = (form, name) => form.elements.namedItem(name);
const exitMode = form => form.querySelector('[name="exit_input_mode"]:checked')?.value || "yaml";

function editableSocksProxy(proxy) {
  return proxy && typeof proxy === "object" && !Array.isArray(proxy)
    && proxy.type === "socks5" && typeof proxy.server === "string"
    && proxy.server.length > 0 && proxy.server.length <= 253 && !/[\s\0]/.test(proxy.server)
    && Number.isInteger(proxy.port) && proxy.port >= 1 && proxy.port <= 65535
    && ["username", "password"].every(key => proxy[key] === undefined
      || (typeof proxy[key] === "string" && proxy[key].length <= 256 && !/[\r\n\0]/.test(proxy[key])))
    && Boolean(proxy.username) === Boolean(proxy.password);
}

function exitConnectionSnapshot(form) {
  return JSON.stringify([exitMode(form), ...["exit_proxy_yaml", "exit_proxy_base",
    ...exitEditorFieldNames.map(name => "exit_field_" + name)].map(name => exitField(form, name)?.value || "")]);
}

function syncExitEditor(form) {
  const state = exitEditorStates.get(form);
  const mode = exitMode(form);
  const busy = form.getAttribute("aria-busy") === "true";
  form.querySelectorAll("[data-exit-input-panel]").forEach(panel => {
    const selected = panel.dataset.exitInputPanel === mode;
    panel.hidden = !selected;
    panel.querySelectorAll("input,textarea,select").forEach(input => {
      input.disabled = busy || !selected;
      input.required = selected && input.hasAttribute("data-exit-required");
    });
  });
  exitField(form, "exit_proxy_base").disabled = busy || mode !== "fields";
  form.querySelector('[name="exit_input_mode"][value="fields"]').disabled = busy || !state.fieldsReady;
}

function fillExitFields(form, proxy) {
  exitField(form, "exit_proxy_base").value = JSON.stringify(proxy);
  exitEditorFieldNames.forEach(name => { exitField(form, "exit_field_" + name).value = proxy[name] ?? ""; });
  exitField(form, "exit_field_password").setCustomValidity("");
}

function exitFieldsAsProxy(form) {
  const proxy = JSON.parse(exitField(form, "exit_proxy_base").value);
  if (!editableSocksProxy(proxy)) throw new Error("请重新载入现有配置，再按字段修改。");
  const result = {...proxy, server: exitField(form, "exit_field_server").value.trim(),
    port: Number(exitField(form, "exit_field_port").value)};
  for (const name of ["username", "password"]) {
    const value = exitField(form, "exit_field_" + name).value;
    if (value) result[name] = value;
    else delete result[name];
  }
  return result;
}

function validateExitFields(form) {
  const username = exitField(form, "exit_field_username");
  const password = exitField(form, "exit_field_password");
  password.setCustomValidity(Boolean(username.value) === Boolean(password.value)
    ? "" : "账号和代理密码必须同时填写或同时清空。");
  for (const name of exitEditorFieldNames) {
    const input = exitField(form, "exit_field_" + name);
    if (!input.checkValidity()) { input.reportValidity(); return false; }
  }
  return true;
}

function beginExitEditorLoad(button) {
  const form = button.closest("[data-exit-edit-form]");
  const state = exitEditorStates.get(form);
  if (!state || state.loading || form.getAttribute("aria-busy") === "true") return null;
  if (state.dirty && !window.confirm("重新载入会放弃当前连接配置草稿，名称和默认出口选择会保留。继续吗？")) return null;
  state.loading = true;
  state.request = {form, button, label: button.textContent, generation: ++state.generation, snapshot: exitConnectionSnapshot(form)};
  return state.request;
}

function isExitEditorLoadCurrent(request) {
  return request.form.isConnected && exitEditorStates.get(request.form)?.generation === request.generation;
}

function finishExitEditorLoad(request) {
  const state = exitEditorStates.get(request.form);
  if (!state || state.generation !== request.generation) return;
  state.loading = false;
  state.request = null;
  request.button.textContent = request.label;
  request.button.disabled = request.form.getAttribute("aria-busy") === "true";
}

function loadExitEditorConfig(button, payload, request) {
  const {form, generation, snapshot} = request;
  const state = exitEditorStates.get(form);
  if (!form.isConnected || !state || state.generation !== generation) return;
  if (form.getAttribute("aria-busy") === "true" || snapshot !== exitConnectionSnapshot(form)) {
    showFeedback("读取期间编辑内容已变化，未覆盖当前草稿。需要时请重新载入。");
    return;
  }
  if (payload.item_id !== exitField(form, "exit_id").value
      || typeof payload.value !== "string" || !payload.value.trim()
      || payload.value.length > 65536 || payload.value.includes("\0")) {
    throw new Error("配置响应无效，当前草稿已保留。");
  }
  const proxyText = payload.proxy ? JSON.stringify(payload.proxy) : "";
  const fieldsReady = proxyText.length <= 65536 && editableSocksProxy(payload.proxy);
  exitField(form, "exit_proxy_yaml").value = payload.value;
  exitField(form, "exit_proxy_base").value = "";
  exitEditorFieldNames.forEach(name => { exitField(form, "exit_field_" + name).value = ""; });
  if (fieldsReady) fillExitFields(form, payload.proxy);
  state.fieldsReady = Boolean(fieldsReady);
  state.dirty = false;
  state.lastMode = fieldsReady ? "fields" : "yaml";
  form.querySelector(`[name="exit_input_mode"][value="${state.lastMode}"]`).checked = true;
  syncExitEditor(form);
  form.querySelector("[data-exit-edit-status]").textContent = fieldsReady
    ? "已载入。未修改的高级参数会保留；预览确认后才保存。"
    : "已载入完整配置。请在下方修改，保留仍需使用的高级参数。";
  // Mark this form as a draft, so saving another card cannot replace it.
  exitField(form, "exit_proxy_base").dispatchEvent(new Event("input", {bubbles: true}));
  (fieldsReady ? exitField(form, "exit_field_server") : exitField(form, "exit_proxy_yaml")).focus();
}

function clearExitEditorSecrets(form) {
  const state = exitEditorStates.get(form);
  if (!state) return;
  ++state.generation; // A late response must not restore discarded secrets.
  if (state.request) {
    state.request.controller?.abort();
    state.request.button.textContent = state.request.label;
    state.request.button.disabled = form.getAttribute("aria-busy") === "true";
  }
  state.request = null;
  state.loading = false;
  state.fieldsReady = false;
  state.dirty = false;
  state.lastMode = "yaml";
  for (const name of ["exit_proxy_base", "exit_proxy_yaml", "exit_field_username", "exit_field_password", "password"]) {
    exitField(form, name).value = "";
  }
  exitField(form, "exit_field_password").setCustomValidity("");
  form.querySelector('[name="exit_input_mode"][value="yaml"]').checked = true;
  exitField(form, "confirmed").checked = false;
  form.querySelector("[data-exit-edit-status]").textContent = "未载入凭据；连接配置留空表示保持不变。";
  syncExitEditor(form);
  document.dispatchEvent(new CustomEvent("server-kit:exit-edit-cleared", {detail: {form}}));
}

function initializeExitEditors() {
  document.querySelectorAll("[data-exit-edit-form]").forEach(form => {
    if (exitEditorStates.has(form)) return;
    const state = {generation: 0, fieldsReady: false, dirty: false, lastMode: "yaml", loading: false, request: null};
    exitEditorStates.set(form, state);
    syncExitEditor(form);
    form.addEventListener("input", event => {
      if (event.target.name === "exit_proxy_yaml") {
        state.dirty = true;
        try { state.fieldsReady = Boolean(editableSocksProxy(JSON.parse(event.target.value))); }
        catch (_) { state.fieldsReady = false; }
        form.querySelector('[name="exit_input_mode"][value="fields"]').disabled = !state.fieldsReady;
      } else if (exitEditorFieldNames.some(name => event.target.name === "exit_field_" + name)) {
        state.dirty = true;
        exitField(form, "exit_field_password").setCustomValidity("");
      }
    });
    form.querySelectorAll('[name="exit_input_mode"]').forEach(radio => radio.addEventListener("change", () => {
      const next = exitMode(form);
      try {
        if (state.lastMode === "fields" && next === "yaml") {
          if (!validateExitFields(form)) throw new Error("请先补全连接参数，再切换完整配置。");
          exitField(form, "exit_proxy_yaml").value = JSON.stringify(exitFieldsAsProxy(form), null, 2) + "\n";
        } else if (next === "fields") {
          const proxy = JSON.parse(exitField(form, "exit_proxy_yaml").value);
          if (!editableSocksProxy(proxy)) throw new Error("该配置请使用完整配置编辑，或重新载入后修改。");
          fillExitFields(form, proxy);
        }
        state.lastMode = next;
      } catch (error) {
        form.querySelector(`[name="exit_input_mode"][value="${state.lastMode}"]`).checked = true;
        showFeedback(error instanceof SyntaxError ? "请使用完整配置编辑，或重新载入后修改。" : error.message);
      }
      syncExitEditor(form);
    }));
    form.addEventListener("submit", event => {
      if (state.loading) {
        event.preventDefault();
        showFeedback("正在载入配置，请等待完成再预览；也可以取消编辑。");
        return;
      }
      if (exitMode(form) === "fields" && !validateExitFields(form)) event.preventDefault();
    });
    form.addEventListener("reset", () => {
      clearExitEditorSecrets(form);
      queueMicrotask(() => {
        state.lastMode = "yaml";
        form.querySelector('[name="exit_input_mode"][value="yaml"]').checked = true;
        syncExitEditor(form);
        form.querySelector("[data-exit-edit-status]").textContent = "未载入凭据；连接配置留空表示保持不变。";
      });
    });
    form.querySelector("[data-exit-edit-cancel]").addEventListener("click", () => {
      if (form.getAttribute("aria-busy") === "true") return;
      form.reset();
      const editor = form.closest("[data-exit-editor]");
      editor.open = false;
      editor.querySelector("summary").focus();
      document.dispatchEvent(new CustomEvent("server-kit:form-discarded", {detail: {form}}));
    });
  });
}

initializeExitEditors();
document.addEventListener("server-kit:content-updated", initializeExitEditors);
document.addEventListener("server-kit:exit-edit-saved", event => clearExitEditorSecrets(event.detail.form));
document.addEventListener("server-kit:form-unlocked", event => {
  if (exitEditorStates.has(event.detail.form)) syncExitEditor(event.detail.form);
});
window.addEventListener("pagehide", () => document.querySelectorAll("[data-exit-edit-form]").forEach(clearExitEditorSecrets));
