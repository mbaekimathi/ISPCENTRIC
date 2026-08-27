(function (global) {
  "use strict";

  var TITLE_BY_TYPE = {
    success: "Success",
    error: "Error",
    warning: "Warning",
    info: "Notice",
    debug: "Notice",
  };

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function normalizeType(type) {
    var t = String(type || "info").toLowerCase();
    if (t.indexOf("error") >= 0) return "error";
    if (t.indexOf("success") >= 0) return "success";
    if (t.indexOf("warning") >= 0) return "warning";
    if (t.indexOf("debug") >= 0) return "debug";
    return "info";
  }

  function iconSvg(type) {
    if (type === "success") {
      return (
        '<svg class="toast-svg" viewBox="0 0 48 48" fill="none" aria-hidden="true">' +
        '<circle class="toast-ring" cx="24" cy="24" r="20" />' +
        '<path class="toast-check" d="M14 24.5l6.5 6.5L34 17" />' +
        "</svg>"
      );
    }
    if (type === "error") {
      return (
        '<svg class="toast-svg" viewBox="0 0 48 48" fill="none" aria-hidden="true">' +
        '<circle class="toast-ring" cx="24" cy="24" r="20" />' +
        '<path class="toast-x" d="M17 17l14 14M31 17L17 31" />' +
        "</svg>"
      );
    }
    if (type === "warning") {
      return (
        '<svg class="toast-svg" viewBox="0 0 48 48" fill="none" aria-hidden="true">' +
        '<path class="toast-tri" d="M24 8l18 32H6L24 8z" />' +
        '<path class="toast-bang" d="M24 20v9" />' +
        '<circle class="toast-dot" cx="24" cy="34" r="1.8" />' +
        "</svg>"
      );
    }
    return (
      '<svg class="toast-svg" viewBox="0 0 48 48" fill="none" aria-hidden="true">' +
      '<circle class="toast-ring" cx="24" cy="24" r="20" />' +
      '<path class="toast-bang" d="M24 22v10" />' +
      '<circle class="toast-dot" cx="24" cy="16.5" r="1.8" />' +
      "</svg>"
    );
  }

  function ensureToastHost() {
    var host = document.getElementById("toast-host");
    if (!host) {
      host = document.createElement("div");
      host.id = "toast-host";
      host.className = "toast-host";
      host.setAttribute("aria-live", "polite");
      host.setAttribute("aria-relevant", "additions");
      document.body.appendChild(host);
    }
    return host;
  }

  function bindToast(toast, ms) {
    var timer;
    function dismiss() {
      if (!toast || toast.classList.contains("is-leaving")) return;
      toast.classList.add("is-leaving");
      window.clearTimeout(timer);
      window.setTimeout(function () {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
        var host = document.getElementById("toast-host");
        if (host && !host.children.length) {
          host.parentNode.removeChild(host);
        }
      }, 320);
    }

    toast.querySelectorAll("[data-toast-dismiss]").forEach(function (btn) {
      btn.addEventListener("click", dismiss);
    });

    if (ms > 0) {
      timer = window.setTimeout(dismiss, ms);
      toast.addEventListener("mouseenter", function () {
        window.clearTimeout(timer);
        toast.classList.add("is-paused");
      });
      toast.addEventListener("mouseleave", function () {
        toast.classList.remove("is-paused");
        timer = window.setTimeout(dismiss, Math.max(1800, ms * 0.4));
      });
    }

    return dismiss;
  }

  function showToast(options) {
    var opts = options || {};
    var type = normalizeType(opts.type);
    var title = escapeHtml((opts.title || TITLE_BY_TYPE[type] || "Notice").trim());
    var text = escapeHtml((opts.text || opts.message || "").trim());
    if (!text && !title) return null;

    var ms = parseInt(opts.ms || opts.duration || 5200, 10);
    if (opts.sticky) ms = 0;

    var host = ensureToastHost();
    host.hidden = false;
    var toast = document.createElement("div");
    toast.className = "toast toast-" + type;
    toast.setAttribute("role", type === "error" ? "alert" : "status");
    if (ms > 0) toast.setAttribute("data-toast-ms", String(ms));

    var actions = opts.actions || [];
    var actionsHtml = "";
    if (actions.length) {
      actionsHtml =
        '<div class="toast-actions">' +
        actions
          .map(function (action, idx) {
            var label = escapeHtml((action.label || action.text || "Action").trim());
            return (
              '<button type="button" class="toast-action-btn" data-toast-action="' +
              idx +
              '">' +
              label +
              "</button>"
            );
          })
          .join("") +
        "</div>";
    }

    toast.innerHTML =
      '<div class="toast-icon" aria-hidden="true">' +
      iconSvg(type) +
      "</div>" +
      '<div class="toast-copy">' +
      '<p class="toast-title">' +
      title +
      "</p>" +
      (text ? '<p class="toast-text">' + text + "</p>" : "") +
      actionsHtml +
      "</div>" +
      '<button type="button" class="toast-dismiss" data-toast-dismiss aria-label="Dismiss">×</button>' +
      (ms > 0 ? '<span class="toast-progress" aria-hidden="true"></span>' : "");

    host.appendChild(toast);

    var dismiss = bindToast(toast, ms);
    actions.forEach(function (action, idx) {
      var btn = toast.querySelector('[data-toast-action="' + idx + '"]');
      if (!btn) return;
      btn.addEventListener("click", function () {
        if (typeof action.onClick === "function") {
          try {
            action.onClick();
          } catch (e) {}
        }
        if (!action.keepOpen) dismiss();
      });
    });

    return { toast: toast, dismiss: dismiss };
  }

  global.showToast = showToast;
  global.ensureToastHost = ensureToastHost;
})(window);
