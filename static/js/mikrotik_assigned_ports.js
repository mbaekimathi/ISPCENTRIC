(function () {
  var root = document.getElementById("mikrotik-assigned-ports-root");
  if (!root) return;

  var liveUrl = root.getAttribute("data-ports-live-url") || "";
  var suspended = root.getAttribute("data-is-suspended") === "1";
  var loading = root.getAttribute("data-ports-loading") === "1";
  var pollTimer = null;
  var pollMs = 4000;

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

  function renderRouterAnalysis(data) {
    var section = root.querySelector("[data-router-analysis]");
    if (!section) return;
    var analysis = data.router_analysis || {};
    var physical = data.physical_ports || [];
    if (!physical.length) {
      setHidden(section, true);
      return;
    }
    setHidden(section, false);

    var noteEl = section.querySelector("[data-router-analysis-note]");
    if (noteEl) noteEl.textContent = analysis.mode_note || "";

    var summaryEl = section.querySelector("[data-router-analysis-summary]");
    if (summaryEl) {
      var summary = analysis.summary || {};
      var bits = [];
      if (summary.online_clients != null) bits.push(summary.online_clients + " online");
      if (summary.offline_clients != null && summary.offline_clients > 0) {
        bits.push(summary.offline_clients + " offline");
      }
      if (summary.total_connections != null && summary.total_connections > 0) {
        bits.push(summary.total_connections + " tracked connections");
      }
      summaryEl.textContent = bits.join(" · ");
      setHidden(summaryEl, !bits.length);
    }

    var ispsEl = section.querySelector("[data-router-analysis-isps]");
    var isps = analysis.isps || [];
    if (ispsEl) {
      if (!isps.length) {
        ispsEl.innerHTML = "";
        setHidden(ispsEl, true);
      } else {
        var ispHtml = isps.map(function (isp, index) {
          var pct = isp.share_pct != null ? isp.share_pct + "% live" : "";
          var weight = isp.weight != null && isp.weight !== "" ? isp.weight + " Mbps weight" : "";
          var meta = [pct, weight, isp.rate_label && isp.rate_label !== "—" ? isp.rate_label : ""]
            .filter(Boolean)
            .join(" · ");
          var statusClass = "is-active";
          var statusLabel = "Active";
          if (isp.status === "slow") {
            statusClass = "is-slow";
            statusLabel = "Slow — sidelined";
          } else if (isp.status === "sidelined") {
            statusClass = "is-sidelined";
            statusLabel = "Sidelined";
          }
          var clients = isp.client_count != null ? isp.client_count + " clients" : "";
          var conns = isp.connection_count != null && isp.connection_count > 0
            ? isp.connection_count + " conn."
            : "";
          var foot = [clients, conns].filter(Boolean).join(" · ");
          return (
            '<article class="mk-router-isp-card ' + statusClass + '">' +
            '<div class="mk-router-isp-card-head">' +
            '<span class="mk-router-isp-index">ISP ' + (index + 1) + "</span>" +
            '<span class="mk-router-isp-status">' + esc(statusLabel) + "</span>" +
            "</div>" +
            '<strong class="mk-router-isp-name">' + esc(isp.label || isp.port || "—") + "</strong>" +
            (meta ? '<p class="mk-help-note">' + esc(meta) + "</p>" : "") +
            (foot ? '<p class="mk-router-isp-foot">' + esc(foot) + "</p>" : "") +
            "</article>"
          );
        }).join("");
        ispsEl.innerHTML = '<div class="mk-router-isp-grid">' + ispHtml + "</div>";
        setHidden(ispsEl, false);
      }
    }

    var clientsWrap = section.querySelector("[data-router-analysis-clients-wrap]");
    var clientsBody = section.querySelector("[data-router-analysis-clients]");
    var emptyEl = section.querySelector("[data-router-analysis-empty]");
    var clients = analysis.clients || [];
    if (clientsWrap && clientsBody) {
      if (!clients.length) {
        clientsBody.innerHTML = "";
        setHidden(clientsBody.closest("table"), true);
        setHidden(emptyEl, false);
        setHidden(clientsWrap, false);
      } else {
        clientsBody.innerHTML = clients.map(function (row) {
          var onlineClass = row.online ? "is-online" : "is-offline";
          var ispClass = "";
          if ((row.isp_port || "") && analysis.isps) {
            analysis.isps.forEach(function (isp) {
              if (isp.port === row.isp_port && isp.status === "slow") ispClass = " is-slow-isp";
            });
          }
          return (
            "<tr class=\"" + onlineClass + ispClass + "\">" +
            "<td>" + esc(row.name || "—") + "</td>" +
            "<td>" + esc(row.account_number || "—") + "</td>" +
            "<td>" + esc((row.service_type || "").toUpperCase()) + "</td>" +
            "<td>" + (row.online && row.ip ? esc(row.ip) : "<span class=\"mk-muted\">Offline</span>") + "</td>" +
            "<td>" + (row.online ? esc(row.isp_label || row.isp_port || "—") : "<span class=\"mk-muted\">—</span>") + "</td>" +
            "<td>" + (row.online && row.connection_count > 0 ? esc(String(row.connection_count)) : "—") + "</td>" +
            "</tr>"
          );
        }).join("");
        setHidden(clientsBody.closest("table"), false);
        setHidden(emptyEl, true);
        setHidden(clientsWrap, false);
      }
    }

    var errEl = section.querySelector("[data-router-analysis-error]");
    if (errEl) {
      var err = (analysis.error || "").trim();
      errEl.textContent = err;
      setHidden(errEl, !err);
    }
  }

  function showError(message) {
    var banner = root.querySelector("[data-assigned-error]");
    var text = root.querySelector("[data-assigned-error-text]");
    var retry = root.querySelector("[data-assigned-retry]");
    if (text) text.textContent = message || "Could not load assigned ports data.";
    setHidden(banner, false);
    setHidden(retry, suspended);
    setHidden(root.querySelector("[data-router-analysis]"), true);
  }

  function clearError() {
    setHidden(root.querySelector("[data-assigned-error]"), true);
  }

  function applyPayload(data) {
    setHidden(root.querySelector("[data-assigned-loading]"), true);
    if (!data || !data.ok) {
      showError((data && data.error) || "Could not load assigned ports data.");
      return;
    }
    clearError();
    renderRouterAnalysis(data);
  }

  function fetchLive() {
    if (!liveUrl || suspended) return;
    fetch(liveUrl, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (res) {
        return res.json().then(function (data) {
          data._status = res.status;
          return data;
        });
      })
      .then(applyPayload)
      .catch(function () {
        showError("Network error while reading live ISP data.");
      });
  }

  function startPolling() {
    if (!liveUrl || suspended) {
      setHidden(root.querySelector("[data-assigned-loading]"), true);
      if (suspended) showError("Activate this MikroTik account to view assigned ports.");
      return;
    }
    fetchLive();
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(fetchLive, pollMs);
  }

  var retryBtn = root.querySelector("[data-assigned-retry]");
  if (retryBtn) {
    retryBtn.addEventListener("click", function () {
      setHidden(root.querySelector("[data-assigned-loading]"), false);
      clearError();
      fetchLive();
    });
  }

  if (loading) startPolling();
  else if (suspended) showError("Activate this MikroTik account to view assigned ports.");
})();
