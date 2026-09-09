"use strict";

// 使用 RFC 7748 Montgomery ladder 在本地计算 WireGuard X25519 公钥。
const X25519_PRIME = (1n << 255n) - 19n;

function mod(value) {
  const result = value % X25519_PRIME;
  return result < 0n ? result + X25519_PRIME : result;
}

function modPow(base, exponent) {
  let result = 1n;
  let factor = mod(base);
  let remaining = exponent;
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) result = mod(result * factor);
    factor = mod(factor * factor);
    remaining >>= 1n;
  }
  return result;
}

function littleEndianToBigInt(bytes) {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) value = (value << 8n) | BigInt(bytes[index]);
  return value;
}

function bigIntToLittleEndian(value) {
  const output = new Uint8Array(32);
  let remaining = value;
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number(remaining & 255n);
    remaining >>= 8n;
  }
  return output;
}

function swap(condition, left, right) {
  return condition ? [right, left] : [left, right];
}

function x25519(privateBytes) {
  const scalar = littleEndianToBigInt(privateBytes);
  const x1 = 9n;
  let x2 = 1n;
  let z2 = 0n;
  let x3 = 9n;
  let z3 = 1n;
  let swapped = false;
  for (let bit = 254; bit >= 0; bit -= 1) {
    const current = ((scalar >> BigInt(bit)) & 1n) === 1n;
    [x2, x3] = swap(swapped !== current, x2, x3);
    [z2, z3] = swap(swapped !== current, z2, z3);
    swapped = current;
    const a = mod(x2 + z2);
    const aa = mod(a * a);
    const b = mod(x2 - z2);
    const bb = mod(b * b);
    const e = mod(aa - bb);
    const c = mod(x3 + z3);
    const d = mod(x3 - z3);
    const da = mod(d * a);
    const cb = mod(c * b);
    x3 = mod((da + cb) ** 2n);
    z3 = mod(x1 * mod((da - cb) ** 2n));
    x2 = mod(aa * bb);
    z2 = mod(e * mod(aa + 121665n * e));
  }
  [x2, x3] = swap(swapped, x2, x3);
  [z2, z3] = swap(swapped, z2, z3);
  return bigIntToLittleEndian(mod(x2 * modPow(z2, X25519_PRIME - 2n)));
}

function standardBase64(bytes) {
  let binary = "";
  for (const value of bytes) binary += String.fromCharCode(value);
  return btoa(binary);
}

function generateKeyMaterial() {
  const privateBytes = crypto.getRandomValues(new Uint8Array(32));
  privateBytes[0] &= 248;
  privateBytes[31] &= 127;
  privateBytes[31] |= 64;
  const presharedBytes = crypto.getRandomValues(new Uint8Array(32));
  return {
    privateKey: standardBase64(privateBytes),
    publicKey: standardBase64(x25519(privateBytes)),
    presharedKey: standardBase64(presharedBytes),
  };
}

function parseBootstrapContext(raw) {
  let context;
  try {
    context = JSON.parse(raw);
  } catch (_error) {
    throw new Error("服务器公开参数不是有效 JSON");
  }
  if (
    context?.schema_version !== 1
    || !/^[A-Za-z0-9+/]{43}=$/.test(context.server_public_key || "")
    || !/^10\.[0-9]+\.[0-9]+\.[0-9]+$/.test(context.suggested_address || "")
    || !Number.isInteger(context.prefix)
    || !Number.isInteger(context.mtu)
    || !Array.isArray(context.endpoints)
    || ![2, 3].includes(context.endpoints.length)
    || typeof context.obfuscation !== "object"
  ) {
    throw new Error("服务器公开参数缺少首个节点所需字段");
  }
  return context;
}

function enrollmentToken(name, address, keys) {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(name)) {
    throw new Error("节点名称格式不正确");
  }
  const value = {
    format: "server-kit-awg-enrollment-v1",
    name,
    address,
    public_key: keys.publicKey,
    preshared_key: keys.presharedKey,
  };
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function renderConfig(context, address, endpoint, keys) {
  const fields = context.obfuscation;
  return `[Interface]\nPrivateKey = ${keys.privateKey}\nAddress = ${address}/${context.prefix}\nMTU = ${context.mtu}\nJc = ${fields.Jc}\nJmin = ${fields.Jmin}\nJmax = ${fields.Jmax}\nS1 = ${fields.S1}\nS2 = ${fields.S2}\nS3 = ${fields.S3}\nS4 = ${fields.S4}\nH1 = ${fields.H1}\nH2 = ${fields.H2}\nH3 = ${fields.H3}\nH4 = ${fields.H4}\nI1 = ${fields.I1}\n\n[Peer]\nPublicKey = ${context.server_public_key}\nPresharedKey = ${keys.presharedKey}\nEndpoint = ${endpoint.host}:${endpoint.port}\nAllowedIPs = ${context.network}\nPersistentKeepalive = 25\n`;
}

function migrateEndpointHost(config, fqdn) {
  const host = String(fqdn || "").trim().replace(/\.$/, "").toLowerCase();
  if (host.length > 253 || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(host)) {
    throw new Error("稳定入口必须是完整主机名（FQDN）");
  }
  const pattern = /^(Endpoint\s*=\s*)(?:\[[^\r\n]+\]|[^:\r\n]+)(:\d{1,5})(\r?)$/gm;
  const matches = [...String(config).matchAll(pattern)];
  if (matches.length !== 1) throw new Error("配置必须且只能包含一个 Endpoint");
  const port = Number(matches[0][2].slice(1));
  if (port < 1 || port > 65535) throw new Error("Endpoint 端口超出范围");
  return String(config).replace(pattern, `$1${host}$2$3`);
}

async function encryptRecoveryBundle(bundle, password) {
  if (password.length < 10) throw new Error("恢复包口令至少需要 10 个字符");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const material = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"],
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 310000 }, material,
    { name: "AES-GCM", length: 256 }, false, ["encrypt"],
  );
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, key,
    new TextEncoder().encode(JSON.stringify(bundle)),
  );
  return JSON.stringify({
    format: "server-kit-awg-recovery-v1", kdf: "PBKDF2-SHA256", iterations: 310000,
    salt: standardBase64(salt), iv: standardBase64(iv),
    ciphertext: standardBase64(new Uint8Array(ciphertext)),
  }, null, 2);
}

globalThis.serverKitAwg = {
  generateKeyMaterial,
  parseBootstrapContext,
  enrollmentToken,
  renderConfig,
  migrateEndpointHost,
  encryptRecoveryBundle,
};
