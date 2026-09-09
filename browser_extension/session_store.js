"use strict";

const PENDING_BUNDLE_KEY = "pending-profile-bundle-v1";
const PENDING_BUNDLE_ALARM = "server-kit-pending-profile-expiry";

async function clearPendingBundle() {
  await chrome.storage.session.remove(PENDING_BUNDLE_KEY);
  await chrome.alarms.clear(PENDING_BUNDLE_ALARM);
}

async function savePendingBundle(state, ttlSeconds = 300) {
  if (!state?.bundle || !Array.isArray(state.bundle.profiles)) {
    throw new Error("临时节点配置格式不正确");
  }
  const boundedTtl = Math.min(300, Math.max(30, Number(ttlSeconds) || 300));
  const stored = { ...state, expiresAt: Date.now() + boundedTtl * 1000 };
  await chrome.storage.session.set({ [PENDING_BUNDLE_KEY]: stored });
  await chrome.alarms.create(PENDING_BUNDLE_ALARM, { when: stored.expiresAt });
  return stored;
}

async function readPendingBundle() {
  const values = await chrome.storage.session.get(PENDING_BUNDLE_KEY);
  const stored = values[PENDING_BUNDLE_KEY];
  if (!stored?.bundle || !Array.isArray(stored.bundle.profiles)) return null;
  if (!Number.isFinite(stored.expiresAt) || stored.expiresAt <= Date.now()) {
    await clearPendingBundle();
    return null;
  }
  return stored;
}

globalThis.serverKitKeyStore = {
  savePendingBundle,
  readPendingBundle,
  clearPendingBundle,
  pendingBundleAlarmName: PENDING_BUNDLE_ALARM,
};
