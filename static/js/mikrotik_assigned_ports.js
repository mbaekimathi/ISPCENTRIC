(function () {
  var root = document.getElementById("mikrotik-assigned-ports-root");
  if (!root) return;

  var liveUrl = root.getAttribute("data-ports-live-url") || "";
  var suspended = root.getAttribute("data-is-suspended") === "1";
  var loading = root.getAttribute("data-ports-loading") === "1";
  var pollTimer = null;
  var pollMs = 4000;
  var livePill = document.querySelector("[data-assigned-live-pill]");

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

  function usageBar(pct) {
    var width = Math.max(0, Math.min(100, Number(pct) || 0));
    return (
      '<div class="mk-assigned-usage-bar" aria-hidden="true">' +
      '<span style="width:' +
      width +
      '%"></span>' +
      "</div>"
    );
  }

  function cell(label, html) {
    return (
      '<td data-label="' +
      esc(label) +
      '">' +
      html +
      "</td>"
    );
  }

  function clientRowHtml(row, analysis) {
    var onlineClass = row.online ? "is-online" : "is-offline";
    var ispClass = "";
    if ((row.isp_port || "") && analysis.isps) {
      analysis.isps.forEach(function (isp) {
        if (isp.port === row.isp_port && isp.status === "slow") ispClass = " is-slow-isp";
      });
    }
    return (
      '<tr class="' +
      onlineClass +
      ispClass +
      '">' +
      cell("Client", clientLink(row)) +
      cell("Account", esc(row.account_number || "—")) +
      cell("Service", esc((row.service_type || "").toUpperCase())) +
      cell(
        "IP",
        row.online && row.ip
          ? esc(row.ip)
          : '<span class="mk-muted">Offline</span>'
      ) +
      cell(
        "Cable",
        row.online
          ? esc(row.lan_port || "—")
          : '<span class="mk-muted">—</span>'
      ) +
      cell(
        "ISP",
        row.online
          ? esc(row.isp_label || row.isp_port || "—")
          : '<span class="mk-muted">—</span>'
      ) +
      cell("Download", '<span class="mk-assigned-num">' + esc(row.download_label || "—") + "</span>") +
      cell("Upload", '<span class="mk-assigned-num">' + esc(row.upload_label || "—") + "</span>") +
      cell("Data", '<span class="mk-assigned-num">' + esc(row.data_label || "—") + "</span>") +
      cell(
        "Uptime",
        row.online && row.uptime
          ? esc(row.uptime)
          : '<span class="mk-muted">—</span>'
      ) +
      "</tr>"
    );
  }

  function clientCardHtml(row) {
    var status = row.online ? "Online" : "Offline";
    var statusClass = row.online ? "is-online" : "is-offline";
    return (
      '<article class="mk-assigned-client-card ' +
      statusClass +
      '">' +
      '<div class="mk-assigned-client-card-head">' +
      "<div>" +
      '<strong class="mk-assigned-client-card-name">' +
      clientLink(row) +
      "</strong>" +
      '<p class="mk-help-note">' +
      esc(row.account_number || "—") +
      " · " +
      esc((row.service_type || "").toUpperCase() || "—") +
      "</p>" +
      "</div>" +
      '<span class="mk-assigned-status-chip">' +
      status +
      "</span>" +
      "</div>" +
      '<dl class="mk-assigned-client-meta">' +
      "<div><dt>IP</dt><dd>" +
      (row.online && row.ip ? esc(row.ip) : "—") +
      "</dd></div>" +
      "<div><dt>Cable</dt><dd>" +
      esc(row.lan_port || "—") +
      "</dd></div>" +
      "<div><dt>ISP</dt><dd>" +
      esc(row.isp_label || row.isp_port || "—") +
      "</dd></div>" +
      "<div><dt>Down</dt><dd>" +
      esc(row.download_label || "—") +
      "</dd></div>" +
      "<div><dt>Up</dt><dd>" +
      esc(row.upload_label || "—") +
      "</dd></div>" +
      "<div><dt>Data</dt><dd>" +
      esc(row.data_label || "—") +
      "</dd></div>" +
      "</dl>" +
      (row.online && row.uptime
        ? '<p class="mk-help-note">Uptime ' + esc(row.uptime) + "</p>"
        : "") +
      "</article>"
    );
  }

  function portCardHtml(port, indexLabel) {
    var statusClass = "is-active";
    var statusLabel = "Active";
    if (port.status === "slow") {
      statusClass = "is-slow";
      statusLabel = "Slow — sidelined";
    } else if (port.status === "sidelined") {
      statusClass = "is-sidelined";
      statusLabel = "Sidelined";
    }
    var kind = port.kind === "lan" ? "Customer port" : indexLabel || "ISP";
    var pct = port.share_pct != null ? port.share_pct : null;
    var metaBits = [];
    if (pct != null) metaBits.push(pct + "% live share");
    if (port.weight != null && port.weight !== "") metaBits.push(port.weight + " Mbps weight");
    if (port.rate_label && port.rate_label !== "—") metaBits.push(port.rate_label);
    var footBits = [];
    var online = port.online_clients != null ? port.online_clients : port.client_count;
    if (online != null) footBits.push(online + " online");
    if (port.connection_count > 0) footBits.push(port.connection_count + " conn.");
    if (port.data_label && port.data_label !== "—") footBits.push(port.data_label + " session");
    return (
      '<article class="mk-router-isp-card mk-assigned-port-card ' +
      statusClass +
      (port.kind === "lan" ? " is-lan" : "") +
      '">' +
      '<div class="mk-router-isp-card-head">' +
      '<span class="mk-router-isp-index">' +
      esc(kind) +
      "</span>" +
      '<span class="mk-router-isp-status">' +
      esc(statusLabel) +
      "</span>" +
      "</div>" +
      '<strong class="mk-router-isp-name">' +
      esc(port.label || port.port || "—") +
      "</strong>" +
      '<div class="mk-assigned-port-rates">' +
      "<span><em>Down</em> " +
      esc(port.download_label || "—") +
      "</span>" +
      "<span><em>Up</em> " +
      esc(port.upload_label || "—") +
      "</span>" +
      "</div>" +
      (pct != null ? usageBar(pct) : "") +
      (metaBits.length
        ? '<p class="mk-help-note">' + esc(metaBits.join(" · ")) + "</p>"
        : "") +
      (footBits.length
        ? '<p class="mk-router-isp-foot">' + esc(footBits.join(" · ")) + "</p>"
        : "") +
      "</article>"
    );
  }

  function renderPortGroups(analysis) {
    var wrap = root.querySelector("[data-assigned-port-groups]");
    if (!wrap) return;
    var groups = [];
    (analysis.lan_ports || []).forEach(function (port) {
      if ((port.clients || []).length) {
        groups.push({
          title: "Cable " + (port.port || ""),
          note: (port.online_clients || 0) + " online · " + (port.rate_label || "—"),
          clients: port.clients,
        });
      }
    });
    var hasLanGroups = groups.length > 0;
    (analysis.isps || []).forEach(function (port, index) {
      if ((port.clients || []).length && !hasLanGroups) {
        groups.push({
          title: port.label || "ISP " + (index + 1),
          note:
            (port.online_clients || port.client_count || 0) +
            " on this ISP · " +
            (port.rate_label || "—"),
          clients: port.clients,
        });
      }
    });
    if (!groups.length) {
      wrap.innerHTML = "";
      setHidden(wrap, true);
      return;
    }
    wrap.innerHTML = groups
      .map(function (group) {
        return (
          '<section class="mk-assigned-port-group">' +
          '<header class="mk-assigned-port-group-head">' +
          "<div><h4>" +
          esc(group.title) +
          "</h4>" +
          '<p class="mk-help-note">' +
          esc(group.note) +
          "</p></div>" +
          "</header>" +
          '<div class="mk-assigned-client-cards is-group">' +
          group.clients
            .map(function (row) {
              return clientCardHtml(row);
            })
            .join("") +
          "</div>" +
          '<div class="mk-router-analysis-table-wrap mk-assigned-group-table">' +
          '<table class="mk-router-analysis-table mk-assigned-clients-table">' +
          "<thead><tr>" +
          "<th>Client</th><th>Account</th><th>Service</th><th>IP</th>" +
          "<th>Cable</th><th>ISP</th><th>Down</th><th>Up</th><th>Data</th><th>Uptime</th>" +
          "</tr></thead>" +
          "<tbody>" +
          group.clients
            .map(function (row) {
              return clientRowHtml(row, analysis);
            })
            .join("") +
          "</tbody></table></div></section>"
        );
      })
      .join("");
    setHidden(wrap, false);
  }

  function renderRouterAnalysis(data) {
    var section = root.querySelector("[data-router-analysis]");
    if (!section) return;
    var analysis = data.router_analysis || {};
    var physical = data.physical_ports || [];
    if (!physical.length && !(analysis.clients || []).length && !(analysis.isps || []).length) {
      setHidden(section, true);
      setHidden(livePill, true);
      return;
    }
    setHidden(section, false);
    setHidden(livePill, false);

    var noteEl = section.querySelector("[data-router-analysis-note]");
    if (noteEl) noteEl.textContent = analysis.mode_note || "";

    var summary = analysis.summary || {};
    var summaryEl = section.querySelector("[data-router-analysis-summary]");
    if (summaryEl) {
      var bits = [];
      if (summary.online_clients != null) bits.push(summary.online_clients + " online");
      if (summary.offline_clients != null && summary.offline_clients > 0) {
        bits.push(summary.offline_clients + " offline");
      }
      if (summary.total_connections != null && summary.total_connections > 0) {
        bits.push(summary.total_connections + " connections");
      }
      summaryEl.textContent = bits.join(" · ");
      setHidden(summaryEl, !bits.length);
    }

    var kpis = section.querySelector("[data-assigned-kpis]");
    if (kpis) {
      var cards = [
        {
          label: "Online clients",
          value: summary.online_clients != null ? String(summary.online_clients) : "—",
        },
        { label: "Live download", value: summary.download_label || "—" },
        { label: "Live upload", value: summary.upload_label || "—" },
        { label: "Session data", value: summary.session_data_label || "—" },
      ];
      kpis.innerHTML = cards
        .map(function (card) {
          return (
            '<div class="mk-assigned-kpi">' +
            '<p class="mk-assigned-kpi-label">' +
            esc(card.label) +
            "</p>" +
            '<p class="mk-assigned-kpi-value">' +
            esc(card.value) +
            "</p>" +
            "</div>"
          );
        })
        .join("");
      setHidden(kpis, false);
    }

    var ispsSection = section.querySelector("[data-router-analysis-isps]");
    var ispGrid = section.querySelector("[data-assigned-isp-grid]");
    var isps = analysis.isps || [];
    if (ispsSection && ispGrid) {
      if (!isps.length) {
        ispGrid.innerHTML = "";
        setHidden(ispsSection, true);
      } else {
        ispGrid.innerHTML = isps
          .map(function (isp, index) {
            return portCardHtml(isp, "ISP " + (index + 1));
          })
          .join("");
        setHidden(ispsSection, false);
      }
    }

    var lanWrap = section.querySelector("[data-assigned-lan-wrap]");
    var lanGrid = section.querySelector("[data-assigned-lan-grid]");
    var lanPorts = (analysis.lan_ports || []).filter(function (port) {
      return (port.client_count || 0) > 0 || (port.role || "") === "lan";
    });
    if (lanWrap && lanGrid) {
      if (!lanPorts.length) {
        lanGrid.innerHTML = "";
        setHidden(lanWrap, true);
      } else {
        lanGrid.innerHTML = lanPorts
          .map(function (port) {
            return portCardHtml(port, "Cable");
          })
          .join("");
        setHidden(lanWrap, false);
      }
    }

    renderPortGroups(analysis);

    var clientsWrap = section.querySelector("[data-router-analysis-clients-wrap]");
    var clientsBody = section.querySelector("[data-router-analysis-clients]");
    var clientCards = section.querySelector("[data-assigned-client-cards]");
    var emptyEl = section.querySelector("[data-router-analysis-empty]");
    var tableWrap = section.querySelector("[data-assigned-all-table-wrap]");
    var caption = section.querySelector("[data-assigned-clients-caption]");
    var clients = analysis.clients || [];
    var hasGroups = !!(
      root.querySelector("[data-assigned-port-groups]") &&
      !root.querySelector("[data-assigned-port-groups]").hidden
    );
    if (clientsWrap && clientsBody) {
      if (!clients.length) {
        clientsBody.innerHTML = "";
        if (clientCards) clientCards.innerHTML = "";
        setHidden(tableWrap, true);
        setHidden(clientCards, true);
        setHidden(emptyEl, false);
        setHidden(clientsWrap, false);
      } else {
        clientsBody.innerHTML = clients
          .map(function (row) {
            return clientRowHtml(row, analysis);
          })
          .join("");
        if (clientCards) {
          clientCards.innerHTML = clients
            .map(function (row) {
              return clientCardHtml(row);
            })
            .join("");
          setHidden(clientCards, hasGroups);
        }
        setHidden(tableWrap, false);
        if (caption) {
          caption.textContent = hasGroups
            ? "Grouped by cable above — full client list below."
            : "Live download / upload, session data, ISP link, and cable port for each assigned customer.";
        }
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
    setHidden(livePill, true);
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
