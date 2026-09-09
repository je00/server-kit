"use strict";

async function copyText(value) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const input = document.createElement("textarea");
  input.value = value;
  input.setAttribute("readonly", "");
  input.style.position = "fixed";
  input.style.opacity = "0";
  document.body.appendChild(input);
  input.select();
  const copied = document.execCommand("copy");
  input.remove();
  if (!copied) throw new Error("复制失败");
}

let pendingSensitiveAction = null;

function openSensitiveAuthModal(button) {
  const modal = document.querySelector("[data-sensitive-auth-modal]");
  const password = modal?.querySelector("[data-sensitive-auth-password]");
  const context = modal?.querySelector("[data-sensitive-auth-context]");
  const error = modal?.querySelector("[data-sensitive-auth-error]");
  if (!modal || !password) return false;
  pendingSensitiveAction = button;
  const actionLabel = button.dataset.secretLabel || ({
    download: "下载客户端配置",
    copy: "复制客户端配置",
    qr: "显示配置二维码",
  }[button.dataset.secretAction] || "读取敏感信息");
  if (context) context.textContent = `“${actionLabel}”需要读取敏感配置，请先验证当前账号密码。`;
  if (error) {
    error.textContent = "";
    error.hidden = true;
  }
  password.value = "";
  modal.hidden = false;
  document.body.classList.add("modal-open");
  window.setTimeout(() => password.focus(), 0);
  return true;
}

function closeSensitiveAuthModal() {
  const modal = document.querySelector("[data-sensitive-auth-modal]");
  if (!modal || modal.hidden) return;
  const password = modal.querySelector("[data-sensitive-auth-password]");
  const error = modal.querySelector("[data-sensitive-auth-error]");
  modal.hidden = true;
  document.body.classList.remove("modal-open");
  if (password) password.value = "";
  if (error) {
    error.textContent = "";
    error.hidden = true;
  }
  pendingSensitiveAction = null;
}

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy-text], [data-copy-target]");
  if (button) {
    const original = button.textContent;
    button.disabled = true;
    try {
      const source = button.dataset.copyTarget
        ? document.querySelector(button.dataset.copyTarget)
        : null;
      const value = source ? source.textContent.trim() : button.dataset.copyText;
      if (!value) throw new Error("没有可复制内容");
      await copyText(value);
      button.textContent = "已复制";
    } catch (_error) {
      button.textContent = "复制失败";
    }
    window.setTimeout(() => {
      button.textContent = original;
      button.disabled = false;
    }, 1600);
    return;
  }

  const secretButton = event.target.closest("[data-secret-action]");
  if (!secretButton) return;
  const form = secretButton.closest("form");
  const csrf = form ? form.querySelector("input[name='csrfmiddlewaretoken']") : null;
  const original = secretButton.textContent;
  secretButton.disabled = true;
  secretButton.textContent = secretButton.dataset.secretAction === "copy" ? "复制中…" : (secretButton.dataset.secretAction === "download" ? "准备中…" : "读取中…");
  try {
    const response = await fetch(secretButton.dataset.endpoint, {
      method: "POST",
      credentials: "same-origin",
      headers: {"Accept": "application/json", "X-CSRFToken": csrf ? csrf.value : ""},
    });
    const payload = await response.json();
    if (
      response.status === 403
      && payload.code === "sensitive_unlock_required"
      && openSensitiveAuthModal(secretButton)
    ) {
      secretButton.textContent = original;
      secretButton.disabled = false;
      return;
    }
    if (!response.ok) throw new Error(payload.error || "读取失败");
    if (secretButton.dataset.secretAction === "copy") {
      await copyText(payload.value);
      secretButton.textContent = "已复制";
    } else if (secretButton.dataset.secretAction === "download") {
      if (!payload.value) throw new Error("配置无效");
      const blob = new Blob([payload.value], {type: "text/plain;charset=utf-8"});
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = secretButton.dataset.downloadName || "amneziawg.conf";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(link.href);
      secretButton.textContent = "已下载";
    } else if (secretButton.dataset.secretAction === "qr") {
      const modal = document.querySelector("[data-qr-modal]");
      const image = modal && modal.querySelector("[data-qr-image]");
      const title = modal && modal.querySelector("[data-qr-title]");
      if (!modal || !image || !title || !payload.image_base64) throw new Error("二维码无效");
      image.src = `data:image/png;base64,${payload.image_base64}`;
      image.alt = `${payload.name} 的二维码`;
      title.textContent = payload.name;
      modal.hidden = false;
      document.body.classList.add("modal-open");
      modal.querySelector(".qr-close").focus();
      secretButton.textContent = original;
    } else if (secretButton.dataset.secretAction === "view") {
      const modal = document.querySelector("[data-secret-modal]");
      const value = modal && modal.querySelector("[data-secret-value]");
      const title = modal && modal.querySelector("[data-secret-title]");
      if (!modal || !value || !title || !payload.value) throw new Error("敏感内容无效");
      value.textContent = payload.value;
      title.textContent = payload.name || "查看配置";
      modal.hidden = false;
      document.body.classList.add("modal-open");
      modal.querySelector("[data-secret-close]").focus();
      secretButton.textContent = original;
    } else {
      throw new Error("操作未登记");
    }
  } catch (_error) {
    secretButton.textContent = "操作失败";
  }
  window.setTimeout(() => {
    secretButton.textContent = original;
    secretButton.disabled = false;
  }, 1600);
});

function closeQrModal() {
  const modal = document.querySelector("[data-qr-modal]");
  if (!modal || modal.hidden) return;
  const image = modal.querySelector("[data-qr-image]");
  modal.hidden = true;
  document.body.classList.remove("modal-open");
  if (image) {
    image.removeAttribute("src");
    image.alt = "";
  }
}

function closeSecretModal() {
  const modal = document.querySelector("[data-secret-modal]");
  if (!modal || modal.hidden) return;
  const value = modal.querySelector("[data-secret-value]");
  modal.hidden = true;
  document.body.classList.remove("modal-open");
  if (value) value.textContent = "";
}

document.querySelectorAll("[data-sensitive-auth-form]").forEach((form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = form.querySelector('button[type="submit"]');
    const error = form.querySelector("[data-sensitive-auth-error]");
    const original = submit?.textContent || "验证并继续";
    if (submit) {
      submit.disabled = true;
      submit.textContent = "验证中…";
    }
    if (error) {
      error.textContent = "";
      error.hidden = true;
    }
    try {
      const response = await fetch(form.action, {
        method: "POST",
        credentials: "same-origin",
        headers: {"Accept": "application/json"},
        body: new FormData(form),
      });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "验证失败");
      const pending = pendingSensitiveAction;
      pendingSensitiveAction = null;
      const modal = form.closest("[data-sensitive-auth-modal]");
      if (modal) modal.hidden = true;
      document.body.classList.remove("modal-open");
      form.reset();
      pending?.click();
    } catch (failure) {
      if (error) {
        error.textContent = failure.message || "验证失败";
        error.hidden = false;
      }
      form.querySelector("[data-sensitive-auth-password]")?.focus();
    } finally {
      if (submit) {
        submit.disabled = false;
        submit.textContent = original;
      }
    }
  });
});

document.addEventListener("click", (event) => {
  if (event.target.closest("[data-qr-close]")) closeQrModal();
  if (event.target.closest("[data-secret-close]")) closeSecretModal();
  if (event.target.closest("[data-sensitive-auth-close]")) closeSensitiveAuthModal();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    closeQrModal();
    closeSecretModal();
    closeSensitiveAuthModal();
  }
});

document.querySelectorAll(".country-picker").forEach((picker) => {
  const inputs = Array.from(picker.querySelectorAll('input[name="countries"]'));
  if (!inputs.length) return;
  const allRegions = inputs.find((input) => input.value === "all");
  const form = picker.closest("form");
  inputs.forEach((input) => {
    input.addEventListener("change", () => {
      if (input === allRegions && input.checked) {
        inputs.forEach((candidate) => { if (candidate !== allRegions) candidate.checked = false; });
      } else if (input !== allRegions && input.checked && allRegions) {
        allRegions.checked = false;
      }
      inputs[0]?.setCustomValidity("");
    });
  });
  form?.addEventListener("submit", (event) => {
    if (inputs.some((input) => input.checked)) return;
    event.preventDefault();
    inputs[0]?.setCustomValidity("请至少选择一个国家或地区");
    inputs[0]?.reportValidity();
  });
});

document.querySelectorAll("[data-exit-input-form]").forEach((form) => {
  const modes = Array.from(form.querySelectorAll('input[name="exit_input_mode"]'));
  const panels = Array.from(form.querySelectorAll("[data-exit-input-panel]"));

  function syncExitInputMode() {
    const selected = modes.find((input) => input.checked)?.value || "fields";
    panels.forEach((panel) => {
      const active = panel.dataset.exitInputPanel === selected;
      panel.hidden = !active;
      panel.querySelectorAll("input, textarea, select").forEach((input) => {
        input.disabled = !active;
        input.required = active && input.hasAttribute("data-exit-required");
      });
    });
  }

  modes.forEach((input) => input.addEventListener("change", syncExitInputMode));
  syncExitInputMode();
});

document.querySelectorAll("[data-permission-form]").forEach((form) => {
  const portMode = form.querySelector('select[name="port_mode"]');
  const ports = form.querySelector('input[name="ports"]');
  const portsField = form.querySelector("[data-permission-ports]");
  if (!portMode || !ports || !portsField) return;

  function syncPermissionFields() {
    const needsPorts = portMode.value === "tcp" || portMode.value === "udp";
    portsField.hidden = !needsPorts;
    ports.disabled = !needsPorts;
    ports.required = needsPorts;
  }

  portMode.addEventListener("change", syncPermissionFields);
  syncPermissionFields();
});

const nodeCreatePanel = document.querySelector("[data-node-create-panel]");
if (nodeCreatePanel && window.location.hash === "#node-create") {
  nodeCreatePanel.open = true;
  window.setTimeout(() => nodeCreatePanel.scrollIntoView({block: "start"}), 0);
}

document.querySelectorAll("[data-countdown]").forEach((container) => {
  let remaining = Number.parseInt(container.dataset.countdown, 10);
  const value = container.querySelector("[data-countdown-value]");
  if (!value || !Number.isFinite(remaining)) return;
  const timer = window.setInterval(() => {
    remaining = Math.max(0, remaining - 1);
    value.textContent = String(remaining);
    if (remaining === 0) {
      window.clearInterval(timer);
      window.setTimeout(() => window.location.reload(), 1200);
    }
  }, 1000);
});

document.querySelectorAll("[data-platform-guide]").forEach((guide) => {
  const buttons = Array.from(guide.querySelectorAll("[data-platform-button]"));
  const panels = Array.from(guide.querySelectorAll("[data-platform-panel]"));
  const known = new Set(panels.map((panel) => panel.dataset.platformPanel));

  function selectPlatform(platform, updateHash) {
    if (!known.has(platform)) return;
    buttons.forEach((button) => {
      const selected = button.dataset.platformButton === platform;
      button.classList.toggle("active", selected);
      button.setAttribute("aria-selected", selected ? "true" : "false");
      button.tabIndex = selected ? 0 : -1;
    });
    const selectedButton = buttons.find((button) => button.dataset.platformButton === platform);
    const tabList = selectedButton?.parentElement;
    if (selectedButton && tabList) {
      tabList.scrollLeft = Math.max(
        0,
        selectedButton.offsetLeft - (tabList.clientWidth - selectedButton.clientWidth) / 2,
      );
    }
    panels.forEach((panel) => {
      const selected = panel.dataset.platformPanel === platform;
      panel.hidden = !selected;
      panel.setAttribute("aria-hidden", selected ? "false" : "true");
    });
    if (updateHash) window.history.replaceState(null, "", `#${platform}`);
  }

  buttons.forEach((button) => {
    button.addEventListener("click", () => selectPlatform(button.dataset.platformButton, true));
    button.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const current = buttons.indexOf(button);
      const next = event.key === "Home"
        ? 0
        : event.key === "End"
          ? buttons.length - 1
          : (current + (event.key === "ArrowRight" ? 1 : -1) + buttons.length) % buttons.length;
      selectPlatform(buttons[next].dataset.platformButton, true);
      buttons[next].focus();
    });
  });
  const requested = window.location.hash.slice(1);
  const agent = window.navigator.userAgent.toLowerCase();
  const detected = agent.includes("iphone") || agent.includes("ipad")
    ? "iphone"
    : agent.includes("android")
      ? "android"
      : agent.includes("mac")
        ? "macos"
        : agent.includes("linux")
          ? "linux"
          : "windows";
  selectPlatform(known.has(requested) ? requested : detected || guide.dataset.defaultPlatform, false);
});

const GUIDE_RETURN_KEY = "server-kit-guide-return";

document.addEventListener("click", (event) => {
  const link = event.target.closest("[data-guide-manager-link]");
  if (!link || !window.matchMedia("(max-width: 900px)").matches) return;

  const panel = link.closest("[data-platform-panel]");
  const step = link.closest(".guide-steps > li[id]");
  if (!panel || !step) return;

  const platform = panel.dataset.platformPanel;
  const device = document.querySelector(`[data-platform-button="${platform}"]`)?.textContent.trim() || "设备";
  const stepTitle = step.querySelector(":scope > strong")?.textContent.trim() || "部署步骤";
  const returnUrl = new URL(window.location.href);
  returnUrl.searchParams.set("returnStep", step.id);
  returnUrl.hash = platform;

  try {
    window.sessionStorage.setItem(GUIDE_RETURN_KEY, JSON.stringify({
      label: `返回 ${device} · ${stepTitle}`,
      url: returnUrl.toString(),
    }));
  } catch (_error) {
    return;
  }

  event.preventDefault();
  window.location.assign(link.href);
});

const guideReturnBar = document.querySelector("[data-guide-return]");
const activeGuide = document.querySelector("[data-platform-guide]");
let storedGuideReturn = null;
try {
  storedGuideReturn = JSON.parse(window.sessionStorage.getItem(GUIDE_RETURN_KEY) || "null");
} catch (_error) {
  storedGuideReturn = null;
}

if (activeGuide) {
  try {
    window.sessionStorage.removeItem(GUIDE_RETURN_KEY);
  } catch (_error) {
    // 浏览器禁用会话存储时，仍可依靠系统返回操作。
  }
  const returnStep = new URL(window.location.href).searchParams.get("returnStep");
  const step = returnStep ? document.getElementById(returnStep) : null;
  if (step) {
    window.setTimeout(() => {
      step.scrollIntoView({ behavior: "smooth", block: "center" });
      const cleanUrl = new URL(window.location.href);
      cleanUrl.searchParams.delete("returnStep");
      window.history.replaceState(null, "", cleanUrl.toString());
    }, 0);
  }
} else if (guideReturnBar && storedGuideReturn?.url && storedGuideReturn?.label) {
  guideReturnBar.href = storedGuideReturn.url;
  guideReturnBar.textContent = storedGuideReturn.label;
  guideReturnBar.hidden = false;
}

if (document.querySelector("[data-task-refresh]")) {
  window.setTimeout(() => window.location.reload(), 2000);
}

const AWG_GENERATOR_SESSION_KEY = "server-kit-awg-generated-bundle-v1";
const AWG_GENERATOR_TTL = 5 * 60 * 1000;

function downloadGeneratedText(name, value) {
  const url = URL.createObjectURL(new Blob([value], {type: "text/plain;charset=utf-8"}));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function readGeneratedBundle() {
  try {
    const value = JSON.parse(window.sessionStorage.getItem(AWG_GENERATOR_SESSION_KEY) || "null");
    if (!value || !Number.isFinite(value.expiresAt) || value.expiresAt <= Date.now()) {
      window.sessionStorage.removeItem(AWG_GENERATOR_SESSION_KEY);
      return null;
    }
    return value;
  } catch (_error) {
    window.sessionStorage.removeItem(AWG_GENERATOR_SESSION_KEY);
    return null;
  }
}

function saveGeneratedBundle(bundle) {
  try {
    window.sessionStorage.setItem(AWG_GENERATOR_SESSION_KEY, JSON.stringify(bundle));
  } catch (_error) {
    // 隐私模式禁用会话存储时，当前页面仍可继续下载和登记。
  }
}

function showGeneratedQr(profile) {
  const modal = document.querySelector("[data-qr-modal]");
  const image = modal?.querySelector("[data-qr-image]");
  const title = modal?.querySelector("[data-qr-title]");
  if (!modal || !image || !title || typeof qrcode !== "function") return;
  const code = qrcode(0, "M");
  code.addData(profile.config);
  code.make();
  image.src = code.createDataURL(5, 16);
  image.alt = `${profile.label}的配置二维码`;
  title.textContent = profile.label;
  modal.hidden = false;
  document.body.classList.add("modal-open");
  modal.querySelector(".qr-close")?.focus();
}

document.querySelectorAll("[data-awg-generator]").forEach((generator) => {
  const form = generator.querySelector("[data-awg-generator-form]");
  const contextSource = generator.querySelector("[data-awg-generator-context]");
  const result = generator.querySelector("[data-awg-generator-result]");
  const list = generator.querySelector("[data-awg-profile-list]");
  const token = generator.querySelector("[data-awg-enrollment-token]");
  const enrollmentForm = generator.querySelector("[data-awg-enrollment-form]");
  const reset = generator.querySelector("[data-awg-generator-reset]");
  const status = generator.querySelector("[data-awg-generator-status]");
  let currentBundle = null;

  function renderBundle(bundle) {
    currentBundle = bundle;
    list.replaceChildren(...bundle.profiles.map((profile) => {
      const row = document.createElement("div");
      row.className = "profile-row";
      const label = document.createElement("strong");
      label.textContent = profile.label;
      const actions = document.createElement("div");
      actions.className = "profile-actions";
      const download = document.createElement("button");
      download.type = "button";
      download.className = "copy-button";
      download.textContent = "下载";
      download.addEventListener("click", () => downloadGeneratedText(profile.fileName, profile.config));
      const copy = document.createElement("button");
      copy.type = "button";
      copy.className = "copy-button";
      copy.textContent = "复制";
      copy.addEventListener("click", async () => {
        await copyText(profile.config);
        copy.textContent = "已复制";
        window.setTimeout(() => { copy.textContent = "复制"; }, 1400);
      });
      const qr = document.createElement("button");
      qr.type = "button";
      qr.className = "copy-button qr-button";
      qr.textContent = "二维码";
      qr.addEventListener("click", () => showGeneratedQr(profile));
      actions.append(download, copy, qr);
      row.append(label, actions);
      return row;
    }));
    token.value = bundle.enrollmentToken;
    form.hidden = true;
    result.hidden = false;
    const remaining = Math.max(1, Math.ceil((bundle.expiresAt - Date.now()) / 60000));
    status.textContent = `配置只保存在当前标签页，约 ${remaining} 分钟后自动清除。`;
  }

  function clearBundle() {
    currentBundle = null;
    window.sessionStorage.removeItem(AWG_GENERATOR_SESSION_KEY);
    list.replaceChildren();
    token.value = "";
    result.hidden = true;
    form.hidden = false;
    form.querySelector('input[name="generator_name"]')?.focus();
  }

  form?.addEventListener("submit", (event) => {
    event.preventDefault();
    const submit = form.querySelector('button[type="submit"]');
    if (submit) submit.disabled = true;
    try {
      if (!globalThis.serverKitAwg) throw new Error("密钥生成模块没有加载");
      const context = globalThis.serverKitAwg.parseBootstrapContext(contextSource.value.trim());
      const name = form.elements.generator_name.value.trim();
      const address = form.elements.generator_address.value.trim() || context.suggested_address;
      if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(name)) throw new Error("节点名称格式不正确");
      if (!/^10\.[0-9]+\.[0-9]+\.[0-9]+$/.test(address)) throw new Error("虚拟 IP 格式不正确");
      const keys = globalThis.serverKitAwg.generateKeyMaterial();
      const labels = {main: "主入口", backup1: "备用 1", backup2: "备用 2"};
      const bundle = {
        name,
        address,
        expiresAt: Date.now() + AWG_GENERATOR_TTL,
        enrollmentToken: globalThis.serverKitAwg.enrollmentToken(name, address, keys),
        profiles: context.endpoints.map((endpoint) => ({
          profile: endpoint.profile,
          label: labels[endpoint.profile] || endpoint.profile,
          fileName: `${name}-${endpoint.profile}.conf`,
          config: globalThis.serverKitAwg.renderConfig(context, address, endpoint, keys),
        })),
      };
      saveGeneratedBundle(bundle);
      renderBundle(bundle);
    } catch (error) {
      window.alert(error.message || "客户端配置生成失败");
    } finally {
      if (submit) submit.disabled = false;
    }
  });

  enrollmentForm?.addEventListener("submit", (event) => {
    if (!currentBundle?.profiles?.length) {
      event.preventDefault();
      clearBundle();
      return;
    }
    downloadGeneratedText(currentBundle.profiles[0].fileName, currentBundle.profiles[0].config);
  });

  reset?.addEventListener("click", clearBundle);
  const restored = readGeneratedBundle();
  if (restored) renderBundle(restored);
});

document.querySelectorAll("[data-dynamic-dns-form]").forEach((form) => {
  const provider = form.querySelector("[data-dynamic-dns-provider]");
  const fieldsets = [...form.querySelectorAll("[data-dynamic-dns-fields]")];
  const submit = form.querySelector("[data-dynamic-dns-submit]");

  function syncProviderFields() {
    const selected = provider?.value || "";
    fieldsets.forEach((fieldset) => {
      const active = fieldset.dataset.dynamicDnsFields === selected;
      fieldset.hidden = !active;
      fieldset.disabled = !active;
    });
    if (submit) {
      submit.hidden = !selected;
      submit.disabled = !selected;
    }
  }

  provider?.addEventListener("change", syncProviderFields);
  syncProviderFields();
});
