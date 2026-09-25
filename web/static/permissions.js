"use strict";

// Batch additions stay local until one root-generated preview is confirmed.
// No optimistic ACL updates and no automatic retries of mutation requests.
(() => {
  const dirtyForms = new Set();
  window.addEventListener("beforeunload", (event) => {
    if (!dirtyForms.size) return;
    event.preventDefault();
    event.returnValue = "";
  });

  document.querySelectorAll("[data-permission-batch]").forEach((form) => {
    const find = (key) => form.querySelector(`[data-permission-${key}]`);
    const rows = find("rows");
    const blank = rows.firstElementChild.cloneNode(true);
    const client = form.querySelector('[name="client"]').value;
    const csrf = form.querySelector('[name="csrfmiddlewaretoken"]').value;
    const card = form.closest(".node-permission-card");
    let phase = "editing";
    let task = null;
    let statusUrl = "";
    let timer = null;
    let polling = false;

    function notice(message, error = "") {
      find("result").hidden = false;
      find("status").textContent = message;
      find("error").textContent = error;
      find("error").hidden = !error;
    }

    function syncRows() {
      const items = [...rows.children];
      items.forEach((row, index) => {
        row.querySelector("[data-rule-number]").textContent = String(index + 1);
        const mode = row.querySelector('[name="port_mode"]');
        const ports = row.querySelector('[name="ports"]');
        const needsPorts = mode.value !== "all";
        row.disabled = phase !== "editing";
        row.querySelector("[data-permission-ports]").hidden = !needsPorts;
        ports.disabled = !needsPorts;
        ports.required = needsPorts;
        const remove = row.querySelector("[data-permission-remove]");
        remove.hidden = items.length === 1;
        remove.setAttribute("aria-label", `移除规则 ${index + 1}`);
      });
      find("add").disabled = items.length >= 20;
      find("draft-count").textContent = `${items.length} / 20 条`;
    }

    function setPhase(value) {
      phase = value;
      const showDrafts = value === "editing" || value === "previewing";
      rows.hidden = !showDrafts;
      find("draft-help").hidden = !showDrafts;
      find("draft-actions").hidden = value !== "editing";
      find("review").hidden = value !== "review";
      find("retry").hidden = true;
      find("continue").hidden = value !== "succeeded";
      form.setAttribute("aria-busy", String(["previewing", "confirming", "running"].includes(value)));
      syncRows();
    }

    function safeUrl(raw) {
      const url = new URL(raw, window.location.href);
      if (!raw || url.origin !== window.location.origin) throw new Error("任务地址无效，请重新获取状态。");
      return url.href;
    }

    async function request(url, payload) {
      const controller = new AbortController();
      const timeout = window.setTimeout(() => controller.abort(), 25000);
      try {
        const response = await fetch(safeUrl(url), {
          method: payload === undefined ? "GET" : "POST", credentials: "same-origin",
          cache: "no-store", signal: controller.signal,
          headers: {Accept: "application/json", "Content-Type": "application/json", "X-CSRFToken": csrf},
          ...(payload === undefined ? {} : {body: JSON.stringify(payload)}),
        });
        if (response.redirected) throw new Error("登录状态可能已失效，请在新标签页登录后重试，当前填写内容已保留。");
        let data;
        try { data = await response.json(); }
        catch (_error) { throw new Error("未收到有效响应，请检查登录状态后重试。当前填写内容已保留。"); }
        if (!response.ok) throw new Error(data.error || "请求失败，当前填写内容已保留。");
        if (!data.task || typeof data.task.id !== "string" || typeof data.task.state !== "string") {
          throw new Error("任务状态无效，未更新权限列表。");
        }
        return data;
      } catch (error) {
        if (error.name === "AbortError" || error instanceof TypeError) {
          throw new Error("连接中断或响应超时。请重新获取状态，不要重复创建任务。");
        }
        throw error;
      } finally { window.clearTimeout(timeout); }
    }

    function rememberTask(data) {
      if (task && data.task.id !== task.id) throw new Error("任务标识不一致，已停止更新。");
      task = data.task;
      if (data.status_url) statusUrl = safeUrl(data.status_url);
      if (data.task_url) {
        find("task-link").href = safeUrl(data.task_url);
        find("task-link").hidden = false;
      }
    }

    function showReview() {
      setPhase("review");
      find("review-title").textContent = task.preview?.title || "确认新增权限";
      find("review-summary").textContent = task.preview?.summary || "请核对本次新增规则。";
      const facts = find("review-facts");
      facts.replaceChildren();
      Object.entries(task.preview?.facts || {}).forEach(([key, value]) => {
        const entry = document.createElement("div");
        const label = document.createElement("dt");
        const detail = document.createElement("dd");
        label.textContent = key;
        detail.textContent = String(value);
        entry.append(label, detail);
        facts.append(entry);
      });
      find("confirm").textContent = `确认添加 ${rows.children.length} 条`;
      find("result").hidden = true;
      find("review-title").focus();
    }

    function renderPermissions(permissions) {
      const list = card.querySelector("[data-permission-list]");
      const fragment = document.createDocumentFragment();
      permissions.forEach((permission, index) => {
        const row = document.createElement("div");
        row.className = `permission-row${index === 0 ? " first-permission-row" : ""}`;
        for (const [className, primary, secondary] of [
          ["permission-target", permission.target_label, permission.ip],
          ["permission-scope", permission.network_label, permission.ports_label],
        ]) {
          const column = document.createElement("span");
          column.className = className;
          const strong = document.createElement("strong");
          strong.textContent = primary || "";
          column.append(strong);
          if (secondary) {
            const small = document.createElement("small");
            small.textContent = secondary;
            column.append(small);
          }
          row.append(column);
        }
        const deletion = document.createElement("form");
        deletion.method = "post";
        deletion.action = form.action;
        Object.entries({csrfmiddlewaretoken: csrf, operation: "deny", client,
          target: permission.target, network: permission.network,
          ports: permission.network === "all" ? "" : permission.ports_label,
        }).forEach(([name, value]) => {
          const input = document.createElement("input");
          input.type = "hidden"; input.name = name; input.value = value || "";
          deletion.append(input);
        });
        const button = document.createElement("button");
        button.className = "copy-button danger-quiet";
        button.type = "submit"; button.textContent = "删除";
        deletion.append(button); row.append(deletion); fragment.append(row);
      });
      list.replaceChildren(fragment);
      card.querySelector("[data-permission-count]").textContent = `${permissions.length} 条规则`;
    }

    function schedulePoll() {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        if (document.hidden) { schedulePoll(); return; }
        poll();
      }, 2000);
    }

    function acceptStatus(data) {
      rememberTask(data);
      if (task.state === "succeeded") {
        setPhase("succeeded");
        dirtyForms.delete(form);
        if (data.client === client && Array.isArray(data.permissions)) {
          renderPermissions(data.permissions);
          notice("本次权限已添加，列表已更新。无需刷新页面。");
        } else {
          notice("任务已成功，权限列表尚未更新。请勿重复添加。", data.permissions_error || "暂时无法读取最新权限。");
          find("retry").textContent = "刷新权限列表";
          find("retry").hidden = false;
        }
        find("status").focus();
      } else if (task.state === "waiting_confirmation") {
        showReview();
        notice("任务尚未提交，可再次确认；将使用同一个任务，不会重复添加。");
      } else if (task.error?.code === "permission_recovery_required") {
        setPhase("recovery");
        notice("自动恢复尚未完成，已暂停本批操作。请保留当前管理连接，先核验服务状态。", task.error.message);
        find("status").focus();
      } else if (task.terminal || ["failed", "cancelled", "rolled_back", "expired", "timed_out"].includes(task.state)) {
        setPhase("editing");
        notice(`任务${task.state_label || "未完成"}，填写内容已保留。`, task.error?.message || "请核对最新状态后重新预览。");
        task = null;
      } else {
        setPhase("running");
        notice(task.progress?.message || task.state_label || "正在添加权限…");
        schedulePoll();
      }
    }

    async function poll() {
      if (polling || !statusUrl) return;
      polling = true;
      find("retry").hidden = true;
      try { acceptStatus(await request(statusUrl)); }
      catch (error) {
        form.setAttribute("aria-busy", "false");
        notice("暂时无法确认最新状态；填写内容已保留，请勿重复提交。", error.message);
        find("retry").textContent = "重新获取进度";
        find("retry").hidden = false;
      } finally { polling = false; }
    }

    form.addEventListener("input", () => { dirtyForms.add(form); });
    rows.addEventListener("change", () => { dirtyForms.add(form); syncRows(); });
    find("add").hidden = false;
    find("draft-count").hidden = false;
    find("preview").textContent = "统一预览";
    find("add").addEventListener("click", () => {
      if (phase !== "editing" || rows.children.length >= 20) return;
      const row = blank.cloneNode(true);
      rows.append(row); dirtyForms.add(form); syncRows();
      row.querySelector("select").focus();
    });
    rows.addEventListener("click", (event) => {
      const remove = event.target.closest("[data-permission-remove]");
      if (!remove || phase !== "editing" || rows.children.length <= 1) return;
      const row = remove.closest("[data-permission-row]");
      const sibling = row.nextElementSibling || row.previousElementSibling;
      row.remove(); dirtyForms.add(form); syncRows(); sibling.querySelector("select").focus();
    });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (phase !== "editing" || !form.reportValidity()) return;
      const rules = [...rows.children].map((row) => ({
        target: row.querySelector('[name="target"]').value,
        network: row.querySelector('[name="port_mode"]').value,
        ports: row.querySelector('[name="port_mode"]').value === "all" ? "" : row.querySelector('[name="ports"]').value,
      }));
      task = null; statusUrl = "";
      find("task-link").hidden = true;
      setPhase("previewing"); dirtyForms.add(form);
      notice("正在核验全部规则，尚未应用…");
      try {
        rememberTask(await request(form.dataset.previewUrl, {client, rules}));
        if (task.state !== "waiting_confirmation") throw new Error("预览状态无效，未自动提交。");
        showReview();
      } catch (error) { setPhase("editing"); notice("无法生成预览，填写内容已保留。", error.message); }
    });
    find("edit").addEventListener("click", () => {
      if (phase !== "review") return;
      task = null; statusUrl = ""; setPhase("editing");
      find("result").hidden = true;
      find("task-link").hidden = true;
      rows.querySelector("select").focus();
    });
    find("confirm").addEventListener("click", async () => {
      if (phase !== "review" || !task) return;
      setPhase("confirming"); notice("正在提交本批规则…");
      try {
        const data = await request(form.dataset.executeUrl, {task_id: task.id});
        rememberTask(data);
        // Read fresh permissions through the status endpoint, even for fast tasks.
        await poll();
      } catch (error) {
        form.setAttribute("aria-busy", "false");
        notice("提交结果暂未确认，请先获取任务状态。不会自动重复提交。", error.message);
        find("retry").textContent = "重新获取进度";
        find("retry").hidden = false;
      }
    });
    find("retry").addEventListener("click", () => poll());
    find("continue").addEventListener("click", () => {
      window.clearTimeout(timer);
      rows.replaceChildren(blank.cloneNode(true));
      task = null; statusUrl = ""; setPhase("editing");
      find("result").hidden = true; find("task-link").hidden = true;
      dirtyForms.delete(form); rows.querySelector("select").focus();
    });
    syncRows();
  });
})();
