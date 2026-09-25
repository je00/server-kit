"use strict";

// Upload bodies can take minutes. Own their full request lifecycle rather than
// using the short native-form double-click guard. Credentials stay in this DOM.
(() => {
  if (typeof XMLHttpRequest === "undefined" || typeof FormData === "undefined") return;

  document.querySelectorAll("[data-upload-form]").forEach((form) => {
    const panel = form.querySelector("[data-upload-progress]");
    const meter = form.querySelector("[data-upload-meter]");
    const status = form.querySelector("[data-upload-status]");
    const error = form.querySelector("[data-upload-error]");
    const recovery = form.querySelector("[data-upload-recovery]");
    const acknowledge = form.querySelector("[data-upload-acknowledge]");
    const submit = form.querySelector('button[type="submit"]');
    const fileInput = form.querySelector('input[type="file"]');
    if (!panel || !meter || !status || !error || !recovery || !acknowledge || !submit || !fileInput) return;

    const originalLabel = submit.textContent;
    const initialSubmitDisabled = submit.disabled;
    let pending = false;
    let needsReview = false;
    let controls = new Map();

    function reveal(message) {
      panel.hidden = false;
      status.textContent = message;
    }

    function restoreControls() {
      for (const [control, disabled] of controls) control.disabled = disabled;
      controls = new Map();
      form.removeAttribute("aria-busy");
      submit.textContent = originalLabel;
    }

    function fail(message, uncertain = false) {
      pending = false;
      restoreControls();
      needsReview = uncertain;
      submit.disabled = initialSubmitDisabled || uncertain;
      recovery.hidden = !uncertain;
      error.textContent = message;
      error.hidden = false;
      reveal(uncertain ? "尚未确认发布结果；请先检查任务记录。" : "未能发布；填写内容和已选文件仍保留。修改后可重新提交。");
      status.focus();
    }

    function responseUrl(value) {
      try {
        const url = new URL(value, window.location.href);
        if (url.origin !== window.location.origin || url.username || url.password) return null;
        return url;
      } catch (_error) { return null; }
    }

    function uploadFailureMessage(request) {
      // Parse only known feedback nodes and use textContent; never insert a
      // returned page, script, exception body or resource URL into this page.
      const type = request.getResponseHeader("Content-Type") || "";
      if (!type.includes("text/html") || request.responseText.length > 2 * 1024 * 1024) return "";
      const page = new DOMParser().parseFromString(request.responseText, "text/html");
      return [...page.querySelectorAll("#main-content > .alert.danger[role='alert']")]
        .map((item) => item.textContent.trim()).filter(Boolean).slice(0, 3).join(" ").slice(0, 1000);
    }

    acknowledge.addEventListener("click", () => {
      if (pending) return;
      needsReview = false;
      submit.disabled = initialSubmitDisabled;
      recovery.hidden = true;
      reveal("请仅在任务记录中确认没有对应发布任务后重新提交；系统不会自动重传。");
      submit.focus();
    });

    window.addEventListener("beforeunload", (event) => {
      if (!pending) return;
      event.preventDefault();
      event.returnValue = "";
    });

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      if (pending || needsReview) return;
      if (!form.reportValidity()) return;
      const file = fileInput.files?.[0];
      const maxBytes = Number(form.dataset.maxUploadBytes);
      if (!file || !file.size || (Number.isFinite(maxBytes) && maxBytes > 0 && file.size > maxBytes)) {
        reveal("请重新选择符合大小要求的文件。");
        error.textContent = !file || !file.size ? "请选择非空文件。" : "文件超过页面标明的上传上限；尚未开始上传。";
        error.hidden = false;
        fileInput.focus();
        return;
      }
      const endpoint = responseUrl(form.action);
      if (!endpoint) {
        fail("上传地址无效，未发送文件。请重新打开文件资源页。");
        return;
      }

      // Capture successful controls (including CSRF/password) before locking
      // them. Let the browser generate the multipart boundary.
      const body = new FormData(form);
      pending = true;
      error.hidden = true;
      error.textContent = "";
      recovery.hidden = true;
      meter.value = 0;
      reveal("准备上传…请保持此页面打开。");
      status.focus();
      controls = new Map([...form.querySelectorAll('input, select, textarea, button[type="submit"]')]
        .map((control) => [control, control.disabled]));
      for (const control of controls.keys()) control.disabled = true;
      form.setAttribute("aria-busy", "true");
      submit.textContent = "正在上传…";

      const request = new XMLHttpRequest();
      let finished = false;
      function settle(callback) {
        if (finished) return;
        finished = true;
        callback();
      }
      request.upload.addEventListener("progress", (progress) => {
        if (finished) return;
        if (!progress.lengthComputable || progress.total <= 0) {
          meter.removeAttribute("value");
          reveal("正在上传…请保持此页面打开。");
          return;
        }
        const percent = Math.min(100, Math.floor(progress.loaded * 100 / progress.total));
        meter.value = percent;
        if (percent === 100) {
          submit.textContent = "正在校验…";
          reveal("文件已传送，服务器正在校验并创建发布任务；尚未发布完成，请勿重复提交。");
        } else {
          reveal(`正在上传 ${percent}%…请保持此页面打开。`);
        }
      });
      request.addEventListener("load", () => settle(() => {
        const destination = responseUrl(request.responseURL);
        if (destination && request.status >= 200 && request.status < 300
          && /^\/tasks\/task-[0-9a-f]{32}\/$/.test(destination.pathname)) {
          // A successful redirect identifies a queued task, not a published
          // file. Do not accept arbitrary return URLs or response markup.
          pending = false;
          reveal("文件已提交到发布任务，正在打开执行进度…");
          window.location.assign(destination.pathname);
          return;
        }
        const expectedPage = responseUrl(form.dataset.uploadReturnUrl);
        const knownValidationFailure = destination && expectedPage
          && destination.pathname === expectedPage.pathname && request.status >= 200 && request.status < 300;
        if (request.status === 401 || request.status === 403 || destination?.pathname === "/login/") {
          fail("登录或安全验证已失效。请在另一标签页重新登录，再返回此页重试；当前文件仍保留。");
        } else if (request.status === 413) {
          fail("文件超过服务器允许的上传大小。请选择更小的文件后重试。");
        } else if (knownValidationFailure) {
          const detail = uploadFailureMessage(request);
          if (detail) fail(detail);
          else fail("服务器未返回可确认的发布结果。请检查任务记录，避免重复发布。", true);
        } else {
          fail("服务器未返回可确认的发布结果。请检查任务记录，避免重复发布。", true);
        }
      }));
      for (const type of ["error", "abort", "timeout"]) {
        request.addEventListener(type, () => settle(() => {
          fail("连接中断或响应超时，服务器可能已经收到文件。系统不会自动重传；请先检查任务记录。", true);
        }));
      }
      try {
        request.open("POST", endpoint.href, true);
        request.withCredentials = true;
        // No short client timeout: a valid 2 GiB upload may take many minutes.
        request.timeout = 0;
        request.setRequestHeader("Accept", "text/html");
        request.send(body);
      } catch (_error) {
        settle(() => fail("无法确认上传是否发出。请检查任务记录后再重试。", true));
      }
    });
  });
})();
