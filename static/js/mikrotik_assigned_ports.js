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
  var autoBalanceInFlight = false;
  var pollInFlight = false;
  var SMART_BALANCE_JOB = "uplink_smart_balance";
  var OFFLINE_KEY = "__offline__";
  var UNKNOWN_KEY = "__unknown__";

  function setHidden(el, hidden) {
    if (!el) return;
    el.hidden = !!hidden;
  }

  function loadingEl() {
    return root.querySelector("[data-assigned-loading]");
  }

  function overviewEl() {
    return root.querySelector("[data-assigned-uplink-overview]");
  }

  function showLoadingPanel() {
    setHidden(loadingEl(), false);
    setHidden(overviewEl(), true);
  }

  function hideLoadingPanel() {
    setHidden(loadingEl(), true);
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

  function clientUplinkKey(row) {
    if (!row.online) return OFFLINE_KEY;
    return (row.isp_port || row.uplink_port || "").trim() || UNKNOWN_KEY;
  }

  function sortClients(rows) {
    return rows.slice().sort(function (a, b) {
      return String(a.name || "").localeCompare(String(b.name || ""));
    });
  }

  function ispSwitchChoices(row, options, columnPort) {
    if (!row.can_switch_isp || !options || !options.length) return [];
    var current = (row.isp_port || row.uplink_port || columnPort || "").trim();
    return options.filter(function (opt) {
      return opt.port && opt.port !== current && !opt.disabled;
    });
  }

  function ispSwitchButtonAttrs(row, opt) {
    return (
      ' data-isp-switch-chip="1"' +
      ' data-customer-id="' +
      esc(String(row.customer_id || "")) +
      '" data-client-ip="' +
      esc(row.ip || "") +
      '" data-client-name="' +
      esc(row.name || "Customer") +
      '" data-target-port="' +
      esc(opt.port) +
      '"'
    );
  }

  function uplinkInlineSwitch(row, options, columnPort) {
    var choices = ispSwitchChoices(row, options, columnPort);
    if (!choices.length) return "";

    if (choices.length >= 3) {
      return (
        '<span class="mk-assigned-uplink-switch mk-assigned-uplink-switch-form">' +
        '<select class="mk-assigned-switch-select mk-assigned-uplink-switch-select" aria-label="Switch internet link">' +
        '<option value="">Switch to…</option>' +
        choices
          .map(function (opt) {
            return (
              '<option value="' +
              esc(opt.port) +
              '">' +
              esc(opt.label || opt.port) +
              "</option>"
            );
          })
          .join("") +
        "</select>" +
        '<button type="button" class="mk-assigned-uplink-switch-btn mk-assigned-switch-submit"' +
        ' data-isp-switch-submit="1"' +
        ' data-customer-id="' +
        esc(String(row.customer_id || "")) +
        '" data-client-ip="' +
        esc(row.ip || "") +
        '" data-client-name="' +
        esc(row.name || "Customer") +
        '" data-target-port=""' +
        ' title="Move to selected link"' +
        " disabled>Switch</button></span>"
      );
    }

    return (
      '<span class="mk-assigned-uplink-switch">' +
      choices
        .map(function (opt) {
          return (
            '<button type="button" class="mk-assigned-uplink-switch-btn"' +
            ispSwitchButtonAttrs(row, opt) +
            ' title="Move to ' +
            esc(opt.label || opt.port) +
            '">' +
            '<span class="mk-assigned-uplink-switch-arrow" aria-hidden="true">→</span> ' +
            esc(opt.label || opt.port) +
            "</button>"
          );
        })
        .join("") +
      "</span>"
    );
  }

  function clientInitial(name) {
    var trimmed = String(name || "").trim();
    if (!trimmed) return "?";
    return esc(trimmed.charAt(0).toUpperCase());
  }

  function clientCard(row, ispOptions, columnPort) {
    var online = !!row.online;
    var phone = (row.phone || "").trim() || "—";
    var statusLabel = online ? "Online" : "Offline";
    var currentIsp = (
      row.isp_label ||
      row.uplink_label ||
      row.isp_port ||
      row.uplink_port ||
      "—"
    ).trim();
    var pinnedBadge = row.isp_pinned
      ? '<span class="mk-assigned-pinned-badge">Pinned</span>'
      : "";
    var inlineSwitch = online ? uplinkInlineSwitch(row, ispOptions, columnPort) : "";
    var uplinkLine = online
      ? '<p class="mk-assigned-client-simple-uplink">' +
        '<span class="mk-assigned-client-simple-uplink-current">On <strong>' +
        esc(currentIsp) +
        "</strong></span> " +
        pinnedBadge +
        inlineSwitch +
        "</p>"
      : "";
    return (
      '<article class="mk-assigned-client-simple ' +
      (online ? "is-online" : "is-offline") +
      '">' +
      '<div class="mk-assigned-client-simple-head">' +
      '<span class="mk-assigned-client-avatar" aria-hidden="true">' +
      clientInitial(row.name) +
      "</span>" +
      '<div class="mk-assigned-client-simple-copy">' +
      '<strong class="mk-assigned-client-simple-name">' +
      clientLink(row) +
      "</strong>" +
      '<p class="mk-assigned-client-simple-phone">' +
      esc(phone) +
      "</p>" +
      uplinkLine +
      "</div>" +
      '<span class="mk-assigned-client-status" title="' +
      esc(statusLabel) +
      '">' +
      '<span class="mk-assigned-client-status-dot" aria-hidden="true"></span>' +
      '<span class="mk-assigned-client-status-text">' +
      esc(statusLabel) +
      "</span>" +
      "</span>" +
      "</div>" +
      "</article>"
    );
  }

  function columnStatusClass(status) {
    if (status === "slow") return "is-slow";
    if (status === "sidelined") return "is-off";
    return "is-up";
  }

  function columnStatusLabel(status) {
    if (status === "slow") return "Slow";
    if (status === "sidelined") return "Off";
    return "Up";
  }

  function buildColumns(analysis) {
    var clients = analysis.clients || [];
    var isps = (analysis.isps || []).filter(function (isp) {
      return (isp.port || "").trim();
    });
    var columns = isps.map(function (isp) {
      return {
        key: isp.port,
        port: isp.port,
        label: isp.label || isp.port,
        status: isp.status || "active",
        isp_index: isp.isp_index,
        clients: [],
      };
    });
    var columnByKey = {};
    columns.forEach(function (col) {
      columnByKey[col.key] = col;
    });

    var unknownCol = {
      key: UNKNOWN_KEY,
      port: "",
      label: "Unmapped",
      status: "unknown",
      isp_index: null,
      clients: [],
    };
    var offlineCol = {
      key: OFFLINE_KEY,
      port: "",
      label: "Offline",
      status: "offline",
      isp_index: null,
      clients: [],
    };

    clients.forEach(function (row) {
      var key = clientUplinkKey(row);
      if (key === OFFLINE_KEY) {
        offlineCol.clients.push(row);
        return;
      }
      if (columnByKey[key]) {
        columnByKey[key].clients.push(row);
        return;
      }
      if (key === UNKNOWN_KEY) {
        unknownCol.clients.push(row);
        return;
      }
      var dynamic = {
        key: key,
        port: key,
        label: row.isp_label || row.uplink_label || key,
        status: "active",
        isp_index: row.uplink_index,
        clients: [row],
      };
      columns.push(dynamic);
      columnByKey[key] = dynamic;
    });

    if (unknownCol.clients.length) columns.push(unknownCol);
    if (offlineCol.clients.length) columns.push(offlineCol);

    columns.forEach(function (col) {
      col.clients = sortClients(col.clients);
    });

    return columns.filter(function (col) {
      return col.clients.length || (col.key !== OFFLINE_KEY && col.key !== UNKNOWN_KEY);
    });
  }

  function renderUplinkColumn(col, ispOptions) {
    var onlineCount = col.clients.filter(function (c) {
      return c.online;
    }).length;
    var isOffline = col.key === OFFLINE_KEY;
    var isUnknown = col.key === UNKNOWN_KEY;
    var idxAttr =
      col.isp_index != null && col.isp_index !== ""
        ? ' data-uplink-index="' + esc(String(col.isp_index)) + '"'
        : "";

    var meta = isOffline
      ? col.clients.length + " customer" + (col.clients.length === 1 ? "" : "s")
      : onlineCount +
        " online" +
        (col.clients.length > onlineCount
          ? " · " + (col.clients.length - onlineCount) + " listed"
          : "");

    var statusBadge =
      isOffline || isUnknown
        ? ""
        : '<span class="mk-assigned-uplink-status ' +
          columnStatusClass(col.status) +
          '">' +
          esc(columnStatusLabel(col.status)) +
          "</span>";

    var html =
      '<section class="mk-assigned-uplink-col ' +
      (isOffline ? "is-offline-col" : isUnknown ? "is-unknown-col" : columnStatusClass(col.status)) +
      '"' +
      idxAttr +
      ' aria-label="' +
      esc(col.label) +
      '">' +
      '<header class="mk-assigned-uplink-col-head">' +
      "<div class=\"mk-assigned-uplink-col-head-copy\">" +
      '<h3 class="mk-assigned-uplink-col-title">' +
      esc(col.label) +
      "</h3>" +
      '<p class="mk-assigned-uplink-col-meta">' +
      esc(meta) +
      "</p>" +
      "</div>" +
      statusBadge +
      "</header>" +
      '<div class="mk-assigned-uplink-col-body">';

    if (!col.clients.length) {
      html +=
        '<p class="mk-assigned-uplink-col-empty">No customers on this link.</p>';
    } else {
      html += col.clients
        .map(function (row) {
          return clientCard(row, ispOptions, col.port || col.key);
        })
        .join("");
    }

    html += "</div></section>";
    return html;
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
      if (moved.length === 1) {
        var first = moved[0];
        title = "Auto balance adjusted";
        message =
          (first.name || "A customer") +
          " is shifting to " +
          (first.to_isp || "another link") +
          " — active streams stay up; new traffic uses the lighter ISP.";
      } else if (moved.length > 1) {
        title = "Auto balance adjusted";
        message =
          moved.length +
          " customers are shifting to lighter links — active browsing stays connected.";
      }
    } else if (insights.imbalanced && insights.bandwidth_drift && insights.bandwidth_drift.sustained) {
      title = "Traffic uneven across uplinks";
      message = data.smart_auto_balance_enabled
        ? "Live bandwidth is skewed — auto balance may move heavy customers to lighter links."
        : "Live bandwidth is skewed — tap Switch next to heavy customers to move them to a lighter link.";
    } else if (insights.imbalanced && insights.dominant_isp) {
      title = "Most customers on " + insights.dominant_isp;
      message = data.smart_auto_balance_enabled
        ? "Auto balance may move customers toward lighter links, or tap Switch manually."
        : "Tap Switch next to a customer to move them to another ISP link.";
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

  function overviewCardClass(status) {
    if (status === "slow") return "is-slow";
    if (status === "sidelined") return "is-off";
    return "is-up";
  }

  function renderUplinkOverview(analysis) {
    var wrap = overviewEl();
    var grid = root.querySelector("[data-assigned-uplink-overview-grid]");
    var stamp = root.querySelector("[data-assigned-overview-stamp]");
    if (!wrap || !grid) return;

    var isps = (analysis.isps || []).filter(function (isp) {
      return (isp.port || "").trim();
    });
    var summary = analysis.summary || {};
    var cards = isps.map(function (isp, index) {
      var status = isp.status || "active";
      var online = Number(isp.online_clients) || 0;
      var total = Number(isp.client_count) || 0;
      var share =
        isp.share_pct != null && isp.share_pct !== ""
          ? String(isp.share_pct) + "% WAN traffic"
          : "";
      var traffic =
        isp.download_label && isp.download_label !== "—"
          ? "↓ " + isp.download_label + " · ↑ " + (isp.upload_label || "—")
          : "";
      var idxAttr =
        isp.isp_index != null && isp.isp_index !== ""
          ? ' data-uplink-index="' + esc(String(isp.isp_index)) + '"'
          : ' data-uplink-index="' + String(index) + '"';

      return (
        '<article class="mk-assigned-overview-card ' +
        overviewCardClass(status) +
        '"' +
        idxAttr +
        ">" +
        '<header class="mk-assigned-overview-card-head">' +
        '<h3 class="mk-assigned-overview-card-title">' +
        esc(isp.label || isp.port) +
        "</h3>" +
        '<span class="mk-assigned-uplink-status ' +
        columnStatusClass(status) +
        '">' +
        esc(columnStatusLabel(status)) +
        "</span>" +
        "</header>" +
        '<p class="mk-assigned-overview-card-stat">' +
        '<strong>' +
        String(online) +
        "</strong> online" +
        (total > online ? " · " + String(total) + " listed" : "") +
        "</p>" +
        (share
          ? '<p class="mk-assigned-overview-card-meta">' + esc(share) + "</p>"
          : "") +
        (traffic
          ? '<p class="mk-assigned-overview-card-meta">' + esc(traffic) + "</p>"
          : "") +
        "</article>"
      );
    });

    var offline = Number(summary.offline_clients) || 0;
    if (offline > 0) {
      cards.push(
        '<article class="mk-assigned-overview-card is-offline-summary">' +
        '<header class="mk-assigned-overview-card-head">' +
        '<h3 class="mk-assigned-overview-card-title">Offline</h3>' +
        "</header>" +
        '<p class="mk-assigned-overview-card-stat">' +
        "<strong>" +
        String(offline) +
        "</strong> customers not connected now" +
        "</p>" +
        "</article>"
      );
    }

    if (!cards.length) {
      setHidden(wrap, true);
      return;
    }

    grid.innerHTML = cards.join("");
    if (stamp) {
      var now = new Date();
      stamp.textContent =
        "Updated " +
        now.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
    }
    hideLoadingPanel();
    setHidden(wrap, false);
  }

  function renderKpis(summary, columns) {
    var row = root.querySelector("[data-assigned-kpi-row]");
    if (!row) return;

    var onlineEl = row.querySelector("[data-assigned-kpi-online]");
    var totalEl = row.querySelector("[data-assigned-kpi-total]");
    var uplinksEl = row.querySelector("[data-assigned-kpi-uplinks]");
    var online = summary.online_clients != null ? summary.online_clients : 0;
    var total = summary.total_clients != null ? summary.total_clients : 0;
    var uplinkCount = (columns || []).filter(function (col) {
      return col.key !== OFFLINE_KEY && col.key !== UNKNOWN_KEY;
    }).length;

    if (onlineEl) onlineEl.textContent = String(online);
    if (totalEl) totalEl.textContent = String(total);
    if (uplinksEl) uplinksEl.textContent = String(uplinkCount);
    setHidden(row, false);
  }

  function renderClients(analysis) {
    var section = root.querySelector("[data-router-analysis]");
    var board = root.querySelector("[data-assigned-client-list]");
    var summaryEl = root.querySelector("[data-assigned-clients-summary]");
    var emptyEl = root.querySelector("[data-router-analysis-empty]");
    var errEl = root.querySelector("[data-router-analysis-error]");
    var kpiRow = root.querySelector("[data-assigned-kpi-row]");
    if (!section || !board) return;

    var clients = analysis.clients || [];
    var summary = analysis.summary || {};

    if (summaryEl) {
      var online = summary.online_clients != null ? summary.online_clients : 0;
      var total = summary.total_clients != null ? summary.total_clients : clients.length;
      summaryEl.textContent = online + " online · " + total + " total";
    }

    if (!clients.length) {
      board.innerHTML = "";
      renderUplinkOverview(analysis);
      setHidden(emptyEl, false);
      setHidden(section, false);
      setHidden(kpiRow, true);
      setHidden(livePill, false);
      return;
    }

    var columns = buildColumns(analysis);
    var ispOptions = analysis.isp_switch_options || [];
    board.innerHTML = columns.map(function (col) {
      return renderUplinkColumn(col, ispOptions);
    }).join("");

    renderKpis(summary, columns);
    renderUplinkOverview(analysis);
    var switchHint = root.querySelector("[data-assigned-switch-hint]");
    if (switchHint) {
      setHidden(switchHint, !analysis.can_switch_clients);
    }
    setHidden(emptyEl, true);
    setHidden(section, false);
    setHidden(livePill, false);

    if (errEl) {
      var err = (analysis.error || "").trim();
      errEl.textContent = err;
      setHidden(errEl, !err);
    }
  }

  function renderAutoBalanceToggle(data) {
    var wrap = document.querySelector("[data-auto-balance-toggle-wrap]");
    var input = wrap ? wrap.querySelector("[data-auto-balance-toggle]") : null;
    if (!wrap || !input) return;
    var show = !!data.can_toggle_auto_balance && !suspended;
    setHidden(wrap, !show);
    if (!show) return;
    input.checked = !!data.smart_auto_balance_enabled;
    input.disabled = autoBalanceInFlight;
    wrap.classList.toggle("is-on", !!data.smart_auto_balance_enabled);
  }

  function setAutoBalance(enabled) {
    if (!applyUrl || autoBalanceInFlight || suspended) return Promise.resolve(null);
    autoBalanceInFlight = true;
    renderAutoBalanceToggle({
      can_toggle_auto_balance: true,
      smart_auto_balance_enabled: enabled,
    });
    var body = new URLSearchParams();
    body.set("action", "set_auto_balance");
    body.set("enabled", enabled ? "1" : "0");
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
        autoBalanceInFlight = false;
        if (!data || !data.ok) {
          fetchLive(true);
          if (typeof window.showToast === "function") {
            window.showToast({
              type: "error",
              title: "Could not update",
              text: (data && data.error) || "Try again in a moment.",
              sticky: true,
            });
          }
          return data;
        }
        if (typeof window.showToast === "function") {
          window.showToast({
            type: "success",
            title: enabled ? "Auto balance on" : "Auto balance off",
            text: data.message || "",
          });
        }
        fetchLive(true);
        return data;
      })
      .catch(function (err) {
        autoBalanceInFlight = false;
        fetchLive(true);
        if (typeof window.showToast === "function") {
          window.showToast({
            type: "error",
            title: "Could not update",
            text: (err && err.message) || "Network error.",
            sticky: true,
          });
        }
        return null;
      });
  }

  function renderPage(data) {
    var analysis = data.router_analysis || {};
    renderAutoBalanceToggle(data || {});
    if (!analysis.ok && !(analysis.clients || []).length) {
      setHidden(root.querySelector("[data-router-analysis]"), true);
      setHidden(root.querySelector("[data-assigned-status-card]"), true);
      setHidden(root.querySelector("[data-assigned-kpi-row]"), true);
      setHidden(livePill, true);
      return;
    }

    renderNotice(data);
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
            title: "Link updated",
            text:
              data.message ||
              clientName +
                " will use " +
                (data.isp_port || targetPort) +
                " for new traffic — no disconnect.",
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
    hideLoadingPanel();
    setHidden(overviewEl(), true);
    if (text) text.textContent = message || "Could not load live data.";
    setHidden(banner, false);
    setHidden(retry, suspended);
    setHidden(root.querySelector("[data-router-analysis]"), true);
    setHidden(root.querySelector("[data-assigned-status-card]"), true);
    setHidden(root.querySelector("[data-assigned-kpi-row]"), true);
    setHidden(livePill, true);
  }

  function clearError() {
    setHidden(root.querySelector("[data-assigned-error]"), true);
  }

  function applyPayload(data) {
    if (!data || !data.ok) {
      showError((data && data.error) || "Could not load live data.");
      return;
    }
    hideLoadingPanel();
    clearError();
    renderPage(data);
    syncJobProgress(data);
    maybeAutoApply(data);
  }

  function fetchLive(force) {
    if (!liveUrl || suspended) return;
    if (pollInFlight && !force) return;
    if (!force && (switchInFlight || applyInFlight || autoBalanceInFlight)) return;
    pollInFlight = true;
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
      })
      .finally(function () {
        pollInFlight = false;
      });
  }

  function startPolling() {
    if (!liveUrl || suspended) {
      hideLoadingPanel();
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
      showLoadingPanel();
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

  var autoBalanceToggle = document.querySelector("[data-auto-balance-toggle]");
  if (autoBalanceToggle) {
    autoBalanceToggle.addEventListener("change", function () {
      var next = !!autoBalanceToggle.checked;
      var prev = !next;
      setAutoBalance(next).then(function (data) {
        if (!data || !data.ok) {
          autoBalanceToggle.checked = prev;
        }
      });
    });
  }

  root.addEventListener("click", function (event) {
    var chip = event.target.closest("[data-isp-switch-chip]");
    if (chip) {
      event.preventDefault();
      requestClientIspSwitch(chip);
      return;
    }
    var submit = event.target.closest("[data-isp-switch-submit]");
    if (!submit) return;
    event.preventDefault();
    var form = submit.closest(".mk-assigned-uplink-switch-form, .mk-assigned-switch-form");
    var select = form ? form.querySelector(".mk-assigned-switch-select") : null;
    var targetPort = select ? (select.value || "").trim() : "";
    if (!targetPort) return;
    submit.setAttribute("data-target-port", targetPort);
    requestClientIspSwitch(submit);
  });
  root.addEventListener("change", function (event) {
    var select = event.target.closest(".mk-assigned-switch-select");
    if (!select) return;
    var form = select.closest(".mk-assigned-uplink-switch-form, .mk-assigned-switch-form");
    var submit = form ? form.querySelector("[data-isp-switch-submit]") : null;
    if (submit) submit.disabled = !(select.value || "").trim() || switchInFlight;
  });

  if (loading) startPolling();
  else if (suspended) showError("Activate this MikroTik account to view live clients.");
})();
