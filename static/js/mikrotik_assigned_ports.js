(function () {
  var root = document.getElementById("mikrotik-assigned-ports-root");
  if (!root) return;

  var liveUrl = root.getAttribute("data-assigned-live-url") || "";
  var applyUrl = root.getAttribute("data-assigned-apply-url") || "";
  var pushStatusUrl = root.getAttribute("data-push-status-url") || "";
  var csrf = root.getAttribute("data-csrf-token") || "";
  var suspended = root.getAttribute("data-is-suspended") === "1";
  var loading = root.getAttribute("data-ports-loading") === "1";
  var pollTimer = null;
  var pollMs = 5000;
  var livePill = document.querySelector("[data-assigned-live-pill]");
  var jobWatcher = null;
  var applyInFlight = false;
  var switchInFlight = false;
  var SMART_BALANCE_JOB = "uplink_smart_balance";

  function setHidden(el, hidden) {
    if (!el) return;
    el.hidden = !!hidden;
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function clientLink(row) {
    var href = row.usage_url || row.detail_url || "";
    var name = esc(row.name || "—");
    if (!href) return name;
    return (
      '<a class="mk-assigned-client-link" href="' +
      esc(href) +
      '">' +
      name +
      "</a>"
    );
  }

  function ispLabel(row) {
    return row.uplink_label || row.isp_label || row.uplink_port || row.isp_port || "—";
  }

  function ispSwitchChips(row, options) {
    if (!row.can_switch_isp || !options || !options.length) return "";
    var current = (row.isp_port || row.uplink_port || "").trim();
    var choices = options.filter(function (opt) {
      return opt.port && opt.port !== current && !opt.disabled;
    });
    if (!choices.length) return "";

    var html = '<div class="mk-assigned-switch-chips">';
    choices.forEach(function (opt) {
      html +=
        '<button type="button" class="mk-assigned-switch-chip"' +
        ' data-isp-switch-chip="1"' +
        ' data-customer-id="' +
        esc(String(row.customer_id || "")) +
        '" data-client-ip="' +
        esc(row.ip || "") +
        '" data-client-name="' +
        esc(row.name || "Customer") +
        '" data-target-port="' +
        esc(opt.port) +
        '">Use ' +
        esc(opt.label || opt.port) +
        "</button>";
    });
    html += "</div>";
    return html;
  }

  function clientRow(row, ispOptions) {
    var online = !!row.online;
    var isp = ispLabel(row);
    var pinned = online && row.isp_pinned;

    return (
      '<article class="mk-assigned-client-row ' +
      (online ? "is-online" : "is-offline") +
      '">' +
      '<div class="mk-assigned-client-row-head">' +
      '<div class="mk-assigned-client-row-id">' +
      '<strong class="mk-assigned-client-row-name">' +
      clientLink(row) +
      "</strong>" +
      (row.account_number
        ? '<span class="mk-assigned-client-row-account">' +
          esc(row.account_number) +
          "</span>"
        : "") +
      "</div>" +
      '<span class="mk-assigned-status-chip">' +
      (online ? "Online" : "Offline") +
      "</span>" +
      "</div>" +
      (online
        ? '<p class="mk-assigned-client-row-isp">' +
          (pinned ? "Pinned on " : "Using ") +
          "<strong>" +
          esc(isp) +
          "</strong></p>" +
          ispSwitchChips(row, ispOptions)
        : "") +
      "</article>"
    );
  }

  function renderNotice(data) {
    var card = root.querySelector("[data-assigned-status-card]");
    if (!card) return;

    var insights = data.balance_insights || {};
    var titleEl = card.querySelector("[data-assigned-balance-title]");
    var msgEl = card.querySelector("[data-assigned-balance-message]");
    var applyBtn = card.querySelector("[data-assigned-balance-apply]");

    var needsAttention =
      !!data.applying_uplink ||
      !!insights.can_auto_enable ||
      !!insights.imbalanced ||
      !!(data.client_rebalance && data.client_rebalance.ok);

    if (!needsAttention) {
      setHidden(card, true);
      return;
    }

    var title = "";
    var message = "";

    if (data.applying_uplink) {
      title = "Setting up smart balance…";
      message =
        (data.uplink_apply_job && data.uplink_apply_job.message) ||
        "Keep this page open for a moment.";
    } else if (insights.can_auto_enable) {
      title = "Two internet links ready";
      message = "Turn on smart balance to spread customers across both links.";
    } else if (data.client_rebalance && data.client_rebalance.ok) {
      var moved = data.client_rebalance.moved || [];
      if (moved.length) {
        var first = moved[0];
        title = "Load balanced automatically";
        message =
          (first.name || "A customer") +
          " moved from " +
          (first.from_isp || "one link") +
          " to " +
          (first.to_isp || "another") +
          ".";
      }
    } else if (insights.imbalanced && insights.dominant_isp) {
      title = "Most customers on " + insights.dominant_isp;
      message =
        "The system moves customers automatically, or tap Use … on a customer below.";
    }

    if (titleEl) titleEl.textContent = title;
    if (msgEl) msgEl.textContent = message;

    if (applyBtn) {
      applyBtn.textContent = insights.auto_enable_label || "Turn on smart balance";
      applyBtn.disabled = !!applyInFlight;
      setHidden(applyBtn, !insights.can_auto_enable || !!data.applying_uplink);
    }

    card.className =
      "mk-assigned-notice " +
      (data.applying_uplink
        ? "is-applying"
        : insights.can_auto_enable
          ? "is-action"
          : "is-info");
    setHidden(card, false);
  }

  function renderIspSummary(analysis) {
    var wrap = root.querySelector("[data-assigned-isp-summary]");
    if (!wrap) return;

    var isps = (analysis.isps || []).filter(function (isp) {
      return (isp.port || "").trim();
    });
    if (isps.length < 2) {
      wrap.innerHTML = "";
      setHidden(wrap, true);
      return;
    }

    wrap.innerHTML = isps
      .map(function (isp, index) {
        var statusClass = "is-up";
        var statusLabel = "Up";
        if (isp.status === "slow") {
          statusClass = "is-slow";
          statusLabel = "Slow";
        } else if (isp.status === "sidelined") {
          statusClass = "is-off";
          statusLabel = "Off";
        }
        var online = isp.online_clients != null ? isp.online_clients : isp.client_count;
        return (
          '<div class="mk-assigned-isp-pill ' +
          statusClass +
          '">' +
          '<span class="mk-assigned-isp-pill-name">' +
          esc(isp.label || isp.port || "ISP " + (index + 1)) +
          "</span>" +
          '<span class="mk-assigned-isp-pill-meta">' +
          esc(String(online != null ? online : 0)) +
          " online · " +
          esc(statusLabel) +
          "</span>" +
          "</div>"
        );
      })
      .join("");
    setHidden(wrap, false);
  }

  function renderClients(analysis) {
    var section = root.querySelector("[data-router-analysis]");
    var list = root.querySelector("[data-assigned-client-list]");
    var summaryEl = root.querySelector("[data-assigned-clients-summary]");
    var emptyEl = root.querySelector("[data-router-analysis-empty]");
    var errEl = root.querySelector("[data-router-analysis-error]");
    if (!section || !list) return;

    var clients = analysis.clients || [];
    var summary = analysis.summary || {};

    if (summaryEl) {
      var online = summary.online_clients != null ? summary.online_clients : 0;
      var total = summary.total_clients != null ? summary.total_clients : clients.length;
      summaryEl.textContent = online + " online · " + total + " total";
    }

    if (!clients.length) {
      list.innerHTML = "";
      setHidden(emptyEl, false);
      setHidden(section, false);
      setHidden(livePill, false);
      return;
    }

    var sorted = clients.slice().sort(function (a, b) {
      if (!!a.online !== !!b.online) return a.online ? -1 : 1;
      return String(a.name || "").localeCompare(String(b.name || ""));
    });

    var ispOptions = analysis.isp_switch_options || [];
    list.innerHTML = sorted
      .map(function (row) {
        return clientRow(row, ispOptions);
      })
      .join("");
    setHidden(emptyEl, true);
    setHidden(section, false);
    setHidden(livePill, false);

    if (errEl) {
      var err = (analysis.error || "").trim();
      errEl.textContent = err;
      setHidden(errEl, !err);
    }
  }

  function renderPage(data) {
    var analysis = data.router_analysis || {};
    if (!analysis.ok && !(analysis.clients || []).length) {
      setHidden(root.querySelector("[data-router-analysis]"), true);
      setHidden(root.querySelector("[data-assigned-isp-summary]"), true);
      setHidden(root.querySelector("[data-assigned-status-card]"), true);
      setHidden(livePill, true);
      return;
    }

    renderNotice(data);
    renderIspSummary(analysis);
    renderClients(analysis);
  }

  function startJobProgress(onComplete) {
    if (!pushStatusUrl || !window.MikrotikJobProgress) return;
    if (jobWatcher && jobWatcher.stop) jobWatcher.stop();
    jobWatcher = window.MikrotikJobProgress.watch({
      jobType: SMART_BALANCE_JOB,
      statusUrl: pushStatusUrl + "?job=" + encodeURIComponent(SMART_BALANCE_JOB),
      onComplete: function () {
        applyInFlight = false;
        if (typeof onComplete === "function") onComplete();
        fetchLive(true);
      },
      onFail: function () {
        applyInFlight = false;
        fetchLive(true);
      },
    });
  }

  function syncJobProgress(data) {
    if (!data) return;
    var scheduled =
      !!(data.balance_auto && (data.balance_auto.scheduled || data.balance_auto.ok)) ||
      !!data.applying_uplink;
    if (scheduled && window.MikrotikJobProgress && !jobWatcher) {
      startJobProgress();
    }
  }

  function requestClientIspSwitch(btn) {
    if (!applyUrl || switchInFlight || !btn) return Promise.resolve(null);
    var customerId = btn.getAttribute("data-customer-id") || "";
    var clientIp = btn.getAttribute("data-client-ip") || "";
    var clientName = btn.getAttribute("data-client-name") || "Customer";
    var targetPort = btn.getAttribute("data-target-port") || "";
    if (!customerId || !clientIp || !targetPort) {
      return Promise.resolve(null);
    }

    switchInFlight = true;
    btn.disabled = true;
    var body = new URLSearchParams();
    body.set("action", "switch_client_isp");
    body.set("customer_id", customerId);
    body.set("client_ip", clientIp);
    body.set("target_port", targetPort);
    if (csrf) body.set("csrfmiddlewaretoken", csrf);

    return fetch(applyUrl, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Requested-With": "XMLHttpRequest",
      },
      body: body.toString(),
    })
      .then(function (res) {
        return res.json().then(function (data) {
          data._status = res.status;
          return data;
        });
      })
      .then(function (data) {
        switchInFlight = false;
        btn.disabled = false;
        if (!data || !data.ok) {
          if (typeof window.showToast === "function") {
            window.showToast({
              type: "error",
              title: "Could not switch",
              text: (data && data.error) || "Try again in a moment.",
              sticky: true,
            });
          }
          return data;
        }
        if (typeof window.showToast === "function") {
          window.showToast({
            type: "success",
            title: "Switched",
            text:
              data.message ||
              clientName + " is now on " + (data.isp_port || targetPort) + ".",
          });
        }
        fetchLive(true);
        return data;
      })
      .catch(function (err) {
        switchInFlight = false;
        btn.disabled = false;
        if (typeof window.showToast === "function") {
          window.showToast({
            type: "error",
            title: "Could not switch",
            text: (err && err.message) || "Network error.",
            sticky: true,
          });
        }
        return null;
      });
  }

  function requestSmartBalanceApply() {
    if (!applyUrl || applyInFlight) return Promise.resolve(null);
    applyInFlight = true;
    var body = new URLSearchParams();
    body.set("action", "auto_enable_smart_balance");
    if (csrf) body.set("csrfmiddlewaretoken", csrf);
    return fetch(applyUrl, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Requested-With": "XMLHttpRequest",
      },
      body: body.toString(),
    })
      .then(function (res) {
        return res.json().then(function (data) {
          data._status = res.status;
          return data;
        });
      })
      .then(function (data) {
        if (!data || !data.ok) {
          applyInFlight = false;
          if (typeof window.showToast === "function") {
            window.showToast({
              type: "error",
              title: "Setup failed",
              text: (data && data.error) || "Could not start smart balance.",
              sticky: true,
            });
          }
          return data;
        }
        startJobProgress();
        fetchLive(true);
        return data;
      })
      .catch(function (err) {
        applyInFlight = false;
        if (typeof window.showToast === "function") {
          window.showToast({
            type: "error",
            title: "Setup failed",
            text: (err && err.message) || "Network error.",
            sticky: true,
          });
        }
        return null;
      });
  }

  function maybeAutoApply(data) {
    if (!data) return;
    if (data.applying_uplink || (data.balance_auto && data.balance_auto.scheduled)) {
      syncJobProgress(data);
    }
  }

  function showError(message) {
    var banner = root.querySelector("[data-assigned-error]");
    var text = root.querySelector("[data-assigned-error-text]");
    var retry = root.querySelector("[data-assigned-retry]");
    if (text) text.textContent = message || "Could not load live data.";
    setHidden(banner, false);
    setHidden(retry, suspended);
    setHidden(root.querySelector("[data-router-analysis]"), true);
    setHidden(root.querySelector("[data-assigned-status-card]"), true);
    setHidden(root.querySelector("[data-assigned-isp-summary]"), true);
    setHidden(livePill, true);
  }

  function clearError() {
    setHidden(root.querySelector("[data-assigned-error]"), true);
  }

  function applyPayload(data) {
    setHidden(root.querySelector("[data-assigned-loading]"), true);
    if (!data || !data.ok) {
      showError((data && data.error) || "Could not load live data.");
      return;
    }
    clearError();
    renderPage(data);
    syncJobProgress(data);
    maybeAutoApply(data);
  }

  function fetchLive(force) {
    if (!liveUrl || suspended) return;
    var url = liveUrl;
    if (force) url += (url.indexOf("?") >= 0 ? "&" : "?") + "refresh=1";
    fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (res) {
        return res
          .json()
          .catch(function () {
            return { ok: false, error: "Invalid response (HTTP " + res.status + ")." };
          })
          .then(function (data) {
            data._status = res.status;
            return data;
          });
      })
      .then(applyPayload)
      .catch(function (err) {
        showError((err && err.message) || "Network error while loading live data.");
      });
  }

  function startPolling() {
    if (!liveUrl || suspended) {
      setHidden(root.querySelector("[data-assigned-loading]"), true);
      if (suspended) showError("Activate this MikroTik account to view live clients.");
      return;
    }
    fetchLive(false);
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(function () {
      fetchLive(false);
    }, pollMs);
  }

  var retryBtn = root.querySelector("[data-assigned-retry]");
  if (retryBtn) {
    retryBtn.addEventListener("click", function () {
      setHidden(root.querySelector("[data-assigned-loading]"), false);
      clearError();
      fetchLive(true);
    });
  }

  var applyBtn = root.querySelector("[data-assigned-balance-apply]");
  if (applyBtn) {
    applyBtn.addEventListener("click", function () {
      requestSmartBalanceApply();
    });
  }

  var clientList = root.querySelector("[data-assigned-client-list]");
  if (clientList) {
    clientList.addEventListener("click", function (event) {
      var chip = event.target.closest("[data-isp-switch-chip]");
      if (!chip) return;
      event.preventDefault();
      requestClientIspSwitch(chip);
    });
  }

  if (loading) startPolling();
  else if (suspended) showError("Activate this MikroTik account to view live clients.");
})();
