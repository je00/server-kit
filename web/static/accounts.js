"use strict";

// Keep account forms and other drafts in place. Passwords live only in the
// current form DOM; they are never serialized to browser storage or URLs.
(() => {
  const list = document.querySelector("[data-account-list]");
  const template = document.querySelector("[data-account-card-template]");
  if (!list || !template) return;
  const pending = new Set();
  const roles = {superuser: "超级管理员", admin: "管理员", viewer: "只读账号"};

  function feedback(form, message, failed) {
    const area = form.querySelector("[data-account-feedback]");
    area.hidden = false;
    area.textContent = message;
    area.className = `alert ${failed ? "danger" : "success"}`;
    area.setAttribute("role", failed ? "alert" : "status");
    area.focus({preventScroll: true});
    area.scrollIntoView({block: "nearest"});
  }

  function updateCard(account) {
    if (!Number.isSafeInteger(account?.id) || account.id < 1 ||
        typeof account.username !== "string" || !Object.hasOwn(roles, account.role) ||
        typeof account.is_active !== "boolean" || typeof account.is_current !== "boolean") {
      throw new Error("账号响应格式无效，请先刷新核验状态，不要重复提交。");
    }
    let card = list.querySelector(`[data-account-card="${account.id}"]`);
    if (!card) {
      card = template.content.firstElementChild.cloneNode(true);
      card.dataset.accountCard = String(account.id);
      card.querySelectorAll('[name="user_id"]').forEach((field) => { field.value = String(account.id); });
      list.append(card);
    }
    card.querySelector("[data-account-name]").textContent = account.username;
    card.querySelector("[data-account-state]").textContent = `${roles[account.role]} · ${account.is_active ? "已启用" : "已停用"}`;
    card.querySelector("[data-account-new-password-label]").textContent = `${account.username} 的新密码`;
    const toggle = card.querySelector("[data-account-toggle]");
    if (toggle) {
      toggle.hidden = account.is_current;
      toggle.classList.toggle("danger-zone", account.is_active);
      toggle.querySelector('[name="operation"]').value = account.is_active ? "disable" : "enable";
      const label = toggle.querySelector("[data-account-toggle-label]");
      label.textContent = account.is_active ? "停用账号" : "启用账号";
      label.classList.toggle("danger-quiet", account.is_active);
      toggle.querySelector("[data-account-toggle-help]").textContent = account.is_active
        ? `停用后 ${account.username} 将无法登录管理网站。`
        : `启用后 ${account.username} 可按原有角色登录。`;
      const button = toggle.querySelector("[data-account-toggle-confirm]");
      button.textContent = account.is_active ? "确认停用" : "确认启用";
      button.classList.toggle("danger-quiet", account.is_active);
    }
    document.querySelector("[data-account-count]").textContent = `${list.querySelectorAll("[data-account-card]").length} 个账号`;
  }

  document.addEventListener("submit", async (event) => {
    const form = event.target.closest?.("[data-account-form]");
    if (!form) return;
    event.preventDefault();
    if (pending.has(form)) return;
    const url = new URL(form.action, window.location.href);
    if (url.origin !== window.location.origin) {
      feedback(form, "账号请求地址无效，未提交。", true);
      return;
    }
    const payload = new FormData(form);
    const button = event.submitter || form.querySelector('[type="submit"]');
    const originalLabel = button.textContent;
    const controls = [...form.querySelectorAll("input, select, button")].map((control) => [control, control.disabled]);
    pending.add(form);
    form.setAttribute("aria-busy", "true");
    controls.forEach(([control]) => { control.disabled = true; });
    button.textContent = "正在提交…";
    let succeeded = false;
    try {
      const response = await fetch(url.href, {
        method: "POST", credentials: "same-origin", cache: "no-store",
        headers: {Accept: "application/json", "X-CSRFToken": String(payload.get("csrfmiddlewaretoken") || "")},
        body: payload,
      });
      if (response.redirected || response.status === 401) {
        throw new Error("登录已失效，当前填写内容仍保留。请在新标签页重新登录后再操作。");
      }
      if (!(response.headers.get("content-type") || "").includes("application/json")) {
        throw new Error(response.status === 403
          ? "安全验证已失效，请先重新登录；当前填写内容仍保留。"
          : "没有收到可确认的结果，请先刷新核验状态，不要重复提交。");
      }
      const result = await response.json();
      if (!response.ok || result.ok !== true) {
        throw new Error(result.error || "未完成账号操作，当前填写内容仍保留。");
      }
      updateCard(result.account);
      succeeded = true;
      // Clear only this completed form; never erase another account's draft.
      form.querySelectorAll('input[type="password"]').forEach((field) => { field.value = ""; });
      form.querySelectorAll('input[type="checkbox"]').forEach((field) => { field.checked = false; });
      feedback(form, result.message || "账号已更新。", false);
    } catch (error) {
      feedback(form, error instanceof TypeError
        ? "连接中断，结果尚未确认。请先刷新核验状态，不要重复提交；当前填写内容仍保留。"
        : error.message || "操作未完成，当前填写内容仍保留。", true);
    } finally {
      pending.delete(form);
      controls.forEach(([control, disabled]) => { control.disabled = disabled; });
      form.removeAttribute("aria-busy");
      // A successful toggle has changed this button's next action.
      if (!(succeeded && button.hasAttribute("data-account-toggle-confirm"))) button.textContent = originalLabel;
    }
  }, true);

  window.addEventListener("beforeunload", (event) => {
    if (!pending.size) return;
    event.preventDefault();
    event.returnValue = "";
  });
  window.addEventListener("pagehide", () => {
    document.querySelectorAll('[data-account-form] input[type="password"]').forEach((field) => { field.value = ""; });
  });
})();
