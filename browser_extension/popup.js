"use strict";

const generatorSection = document.getElementById("generator-section");
const profilesSection = document.getElementById("profiles");
const result = document.getElementById("result");
let currentBundle = null;
let pendingExpiryTimer = null;
let migratedConfig = "";

function showResult(message, kind = "") {
  result.hidden = false;
  result.className = kind;
  result.textContent = message;
}

function downloadText(name, value, type = "text/plain") {
  const url = URL.createObjectURL(new Blob([value], { type }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function showQr(title, value) {
  const code = qrcode(0, "M");
  code.addData(value);
  code.make();
  document.getElementById("qr-title").textContent = title;
  document.getElementById("qr-image").src = code.createDataURL(5, 16);
  document.getElementById("qr-dialog").hidden = false;
}

function clearQr() {
  document.getElementById("qr-image").removeAttribute("src");
  document.getElementById("qr-dialog").hidden = true;
}

function clearPendingUi(message) {
  if (pendingExpiryTimer !== null) clearTimeout(pendingExpiryTimer);
  pendingExpiryTimer = null;
  currentBundle = null;
  clearQr();
  profilesSection.hidden = true;
  generatorSection.hidden = false;
  showResult(message, "success");
}

function renderPendingBundle(state) {
  currentBundle = state.bundle;
  const labels = { main: "主入口", backup1: "备用 1", backup2: "备用 2" };
  const list = document.getElementById("profile-list");
  list.replaceChildren(...currentBundle.profiles.map((profile) => {
    const row = document.createElement("div");
    row.className = "profile-row";
    const label = document.createElement("strong");
    label.textContent = labels[profile.profile] || profile.profile;
    const copy = document.createElement("button");
    copy.type = "button"; copy.className = "small"; copy.textContent = "复制";
    copy.addEventListener("click", async () => {
      await navigator.clipboard.writeText(profile.config);
      showResult(`${label.textContent}配置已复制`, "success");
    });
    const download = document.createElement("button");
    download.type = "button"; download.className = "small"; download.textContent = "下载";
    download.addEventListener("click", () => downloadText(profile.fileName, profile.config));
    const qr = document.createElement("button");
    qr.type = "button"; qr.className = "small"; qr.textContent = "二维码";
    qr.addEventListener("click", () => showQr(`${label.textContent}二维码`, profile.config));
    row.append(label, copy, download, qr);
    return row;
  }));
  document.getElementById("enrollment-token").value = state.enrollmentToken;
  generatorSection.hidden = true;
  profilesSection.hidden = false;
  const remainingSeconds = Math.max(1, Math.ceil((state.expiresAt - Date.now()) / 1000));
  document.getElementById("pending-retention").textContent =
    `配置和登记信息仅存于浏览器会话内存，约 ${remainingSeconds} 秒后自动清除。`;
  if (pendingExpiryTimer !== null) clearTimeout(pendingExpiryTimer);
  pendingExpiryTimer = setTimeout(async () => {
    await globalThis.serverKitKeyStore.clearPendingBundle();
    clearPendingUi("临时配置已到期清除，请重新生成。");
  }, Math.max(0, state.expiresAt - Date.now()));
}

async function showProfiles(name, address, context, keys) {
  const profiles = context.endpoints.map((endpoint) => ({
    profile: endpoint.profile,
    fileName: `${name}-${endpoint.profile}.conf`,
    config: globalThis.serverKitAwg.renderConfig(context, address, endpoint, keys),
  }));
  const bundle = { name, address, created_at: new Date().toISOString(), profiles };
  const enrollmentToken = globalThis.serverKitAwg.enrollmentToken(name, address, keys);
  const state = await globalThis.serverKitKeyStore.savePendingBundle({ bundle, enrollmentToken }, 300);
  renderPendingBundle(state);
}

document.getElementById("server-context").addEventListener("change", (event) => {
  try {
    const context = globalThis.serverKitAwg.parseBootstrapContext(event.target.value.trim());
    if (!document.getElementById("node-address").value.trim()) {
      document.getElementById("node-address").value = context.suggested_address;
    }
    showResult("服务器公开参数有效。", "success");
  } catch (error) {
    showResult(error.message || "服务器公开参数无效", "error");
  }
});

document.getElementById("generator-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector("button");
  button.disabled = true;
  try {
    const context = globalThis.serverKitAwg.parseBootstrapContext(
      document.getElementById("server-context").value.trim(),
    );
    const name = document.getElementById("node-name").value.trim();
    const address = document.getElementById("node-address").value.trim() || context.suggested_address;
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(name)) throw new Error("节点名称格式不正确");
    if (!/^10\.[0-9]+\.[0-9]+\.[0-9]+$/.test(address)) throw new Error("虚拟 IP 格式不正确");
    const keys = globalThis.serverKitAwg.generateKeyMaterial();
    await showProfiles(name, address, context, keys);
    showResult("已在本地生成。请复制登记信息到管理网站。", "success");
  } catch (error) {
    currentBundle = null;
    showResult(error.message || "本地生成失败", "error");
  } finally {
    button.disabled = false;
  }
});

document.getElementById("copy-enrollment-token").addEventListener("click", async () => {
  const token = document.getElementById("enrollment-token").value;
  if (!token) return;
  await navigator.clipboard.writeText(token);
  showResult("节点登记信息已复制，可以粘贴到管理网站。", "success");
});

function clearMigratedConfig(message = "") {
  migratedConfig = "";
  document.getElementById("migration-config").value = "";
  document.getElementById("migrated-config").value = "";
  document.getElementById("migration-result").hidden = true;
  if (message) showResult(message, "success");
}

document.getElementById("endpoint-migration-form").addEventListener("submit", (event) => {
  event.preventDefault();
  try {
    migratedConfig = globalThis.serverKitAwg.migrateEndpointHost(
      document.getElementById("migration-config").value,
      document.getElementById("migration-fqdn").value,
    );
    document.getElementById("migrated-config").value = migratedConfig;
    document.getElementById("migration-result").hidden = false;
    showResult("Endpoint 主机已在本地替换；请核对端口和密钥字段后逐份导入。", "success");
  } catch (error) {
    migratedConfig = "";
    document.getElementById("migration-result").hidden = true;
    showResult(error.message || "配置迁移失败", "error");
  }
});

document.getElementById("copy-migrated-config").addEventListener("click", async () => {
  if (!migratedConfig) return;
  await navigator.clipboard.writeText(migratedConfig);
  showResult("迁移后配置已复制。", "success");
});

document.getElementById("download-migrated-config").addEventListener("click", () => {
  if (!migratedConfig) return;
  downloadText("awg-migrated.conf", migratedConfig);
  showResult("迁移后配置已下载。", "success");
});

document.getElementById("clear-migrated-config").addEventListener("click", () => {
  clearMigratedConfig("迁移配置已从页面清除。");
});

document.getElementById("qr-close").addEventListener("click", clearQr);

document.getElementById("clear-pending").addEventListener("click", async () => {
  await globalThis.serverKitKeyStore.clearPendingBundle();
  clearPendingUi("临时配置已清除。");
});

document.getElementById("download-recovery").addEventListener("click", async () => {
  try {
    if (!currentBundle) throw new Error("当前没有可导出的配置");
    const password = document.getElementById("recovery-password").value;
    const encrypted = await globalThis.serverKitAwg.encryptRecoveryBundle(currentBundle, password);
    downloadText(`${currentBundle.name}-recovery.json`, encrypted, "application/json");
    showResult("加密恢复包已下载", "success");
  } catch (error) {
    showResult(error.message || "恢复包生成失败", "error");
  }
});

async function initialize() {
  try {
    const restored = await globalThis.serverKitKeyStore.readPendingBundle();
    if (restored) {
      renderPendingBundle(restored);
      showResult("已恢复刚才生成的配置。", "success");
    }
  } catch {
    await globalThis.serverKitKeyStore.clearPendingBundle();
  }
}

initialize().catch(() => showResult("无法初始化本地密钥生成器", "error"));
