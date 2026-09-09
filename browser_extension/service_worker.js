"use strict";

importScripts("session_store.js");

// 0.4 起不再持有审批签名密钥；升级时永久清除旧版数据库。
indexedDB.deleteDatabase("server-kit-signer");

chrome.action.onClicked.addListener(() => {
  chrome.tabs.create({ url: chrome.runtime.getURL("popup.html") });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== globalThis.serverKitKeyStore.pendingBundleAlarmName) return;
  globalThis.serverKitKeyStore.clearPendingBundle().catch(() => {});
});
