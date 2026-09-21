(function () {
  var root = document.getElementById("mk-detail-analytics");
  if (!root) return;

  var analyticsUrl = root.getAttribute("data-detail-analytics-url") || "";
  var suspended = root.getAttribute("data-is-suspended") === "1";
  var pollTimer = null;
  var pollMs = 15000;
  var healthChart = null;
  var inFlight = false;
  var lastLiveStatus = "";
  var lastLiveError = "";

  var initialEl = document.getElementById("mikrotik-initial-detail-analytics");
  var initialAnalytics = null;
  if (initialEl) {
    try {
      initialAnalytics = JSON.parse(initialEl.textContent || "null");
    } catch (e) {
      initialAnalytics = null;
    }
  }

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

  function chartDefaults() {
    return {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: function (ctx) {
              var val = ctx.parsed.y;
              return val == null ? "No data" : "Health " + val + "%";
            },
          },
        },
      },
      scales: {
        x: {
          grid: { display: false },
          ticks: { maxTicksLimit: 8, maxRotation: 0 },
        },
        y: {
          min: 0,
          max: 100,
          ticks: { stepSize: 25, callback: function (v) { return v + "%"; } },
        },
      },
    };
  }

  function paintHealthTrend(trend) {
    var canvas = document.getElementById("mk-detail-health-chart");
    if (!canvas || !window.Chart || !trend || !trend.ok) return;
    var labels = trend.labels || [];
    var datasets = (trend.datasets || []).map(function (ds) {
      return Object.assign({}, ds, { fill: true, spanGaps: true });
    });
    if (!healthChart) {
      healthChart = new Chart(canvas, {
        type: "line",
        data: { labels: labels, datasets: datasets },
        options: chartDefaults(),
      });
    } else {
      healthChart.data.labels = labels;
      healthChart.data.datasets = datasets;
      healthChart.update("none");
    }

    var scoreEl = root.querySelector("[data-detail-health-score]");
    if (scoreEl) {
      scoreEl.textContent =
        trend.current_score != null ? String(trend.current_score) + "%" : "—";
    }
    var samplesWrap = root.querySelector("[data-detail-health-samples]");
    var samplesEl = root.querySelector("[data-detail-health-sample-count]");
    if (samplesWrap && samplesEl) {
      var count = trend.sample_count != null ? trend.sample_count : 0;
      samplesEl.textContent = String(count);
      setHidden(samplesWrap, !count);
    }
  }

  function renderHealthDrops(drops) {
    var section = root.querySelector("[data-detail-health-drops]");
    var list = root.querySelector("[data-detail-drop-list]");
    if (!section || !list) return;
    var events = (drops && drops.events) || [];
    if (!events.length) {
      setHidden(section, true);
      list.innerHTML = "";
      return;
    }
    list.innerHTML = events
      .map(function (row) {
        var detail = "";
        if (row.from_score != null && row.to_score != null) {
          detail = "Health " + row.from_score + "% → " + row.to_score + "%";
        }
        return (
          '<li class="mk-detail-drop' +
          (row.current ? " is-now" : "") +
          '">' +
          '<span class="mk-detail-drop-time">' +
          esc(row.at || "—") +
          "</span>" +
          "<div>" +
          '<p class="mk-detail-drop-title">' +
          esc(row.reason || "Health dropped") +
          "</p>" +
          (detail ? '<p class="mk-detail-drop-meta">' + esc(detail) + "</p>" : "") +
          "</div>" +
          "</li>"
        );
      })
      .join("");
    setHidden(section, false);
  }

  function renderInternetSetup(setup) {
    setup = setup || {};
    var modeEl = root.querySelector("[data-detail-setup-mode]");
    var metaEl = root.querySelector("[data-detail-setup-meta]");
    var statusEl = root.querySelector("[data-detail-setup-status]");
    var healthEl = root.querySelector("[data-detail-setup-health]");
    var leadEl = root.querySelector("[data-detail-setup-lead]");

    if (modeEl) modeEl.textContent = setup.mode_label || setup.mode || "Single WAN";
    if (metaEl) {
      metaEl.textContent = setup.meta || "";
      setHidden(metaEl, !setup.meta);
    }
    if (leadEl && setup.mode_note) {
      leadEl.textContent = setup.mode_note;
    }

    if (statusEl) {
      var statusMsg = setup.status_message || "";
      if (statusMsg) {
        statusEl.textContent = statusMsg;
        statusEl.className =
          "mk-banner mk-detail-setup-status " +
          (setup.status_level === "ok"
            ? "is-ok"
            : setup.status_level === "warn"
              ? "is-warn"
              : "is-info");
        setHidden(statusEl, false);
      } else {
        setHidden(statusEl, true);
      }
    }

    if (healthEl) {
      var healthMsg = setup.health_message || "";
      if (healthMsg) {
        healthEl.textContent = healthMsg;
        healthEl.className =
          "mk-detail-setup-health " +
          (setup.health_level === "ok"
            ? "is-ok"
            : setup.health_level === "warn"
              ? "is-warn"
              : "");
        setHidden(healthEl, false);
      } else {
        setHidden(healthEl, true);
      }
    }
  }

  function ispStatusClass(status) {
    if (status === "slow") return "is-slow";
    if (status === "sidelined") return "is-off";
    return "";
  }

  function ispStatusLabel(status) {
    if (status === "slow") return "Slow";
    if (status === "sidelined") return "Off";
    return "Up";
  }

  function renderIspCard(row) {
    var status = row.status || "active";
    var online = row.online_clients != null ? row.online_clients : 0;
    var total = row.client_count != null ? row.client_count : 0;
    var down = row.download_label || "—";
    var up = row.upload_label || "—";
    var data = row.data_label || "—";
    return (
      '<article class="mk-router-isp-card ' +
      ispStatusClass(status) +
      '">' +
      '<div class="mk-router-isp-card-head">' +
      '<span class="mk-router-isp-index">' +
      esc(row.label || row.port || "ISP") +
      "</span>" +
      '<span class="mk-router-isp-status">' +
      esc(ispStatusLabel(status)) +
      "</span>" +
      "</div>" +
      '<strong class="mk-router-isp-name">' +
      esc(row.port || "—") +
      "</strong>" +
      '<div class="mk-assigned-port-rates">' +
      "<span><em>Down</em> " +
      esc(down) +
      "</span>" +
      "<span><em>Up</em> " +
      esc(up) +
      "</span>" +
      "<span><em>Data</em> " +
      esc(data) +
      "</span>" +
      "</div>" +
      '<p class="mk-router-isp-foot">' +
      esc(online + " online · " + total + " assigned") +
      "</p>" +
      "</article>"
    );
  }

  function renderInternetAnalytics(analytics) {
    var block = root.querySelector("[data-detail-internet-analytics]");
    var loading = root.querySelector("[data-detail-analytics-loading]");
    var kpiRow = root.querySelector("[data-detail-kpi-row]");
    var grid = root.querySelector("[data-detail-isp-grid]");
    var emptyEl = root.querySelector("[data-detail-analytics-empty]");
    var errEl = root.querySelector("[data-detail-analytics-error]");
    var noteEl = root.querySelector("[data-detail-internet-note]");
    if (!block || suspended) return;

    if (analytics && analytics.pending) {
      setHidden(loading, false);
      setHidden(kpiRow, true);
      setHidden(grid, true);
      setHidden(emptyEl, true);
      if (errEl) setHidden(errEl, true);
      return;
    }

    setHidden(loading, true);

    if (!analytics || !analytics.ok) {
      var err = (analytics && analytics.error) || "";
      if (errEl) {
        errEl.textContent = err || "Internet analytics unavailable right now.";
        setHidden(errEl, !err);
      }
      setHidden(kpiRow, true);
      setHidden(grid, true);
      setHidden(emptyEl, !!err);
      return;
    }

    if (errEl) setHidden(errEl, true);

    var summary = analytics.summary || {};
    var isps = (analytics.isps || []).filter(function (row) {
      return (row.port || "").trim();
    });

    if (noteEl && analytics.mode_note) {
      noteEl.textContent = analytics.mode_note;
    }

    if (kpiRow) {
      var onlineEl = kpiRow.querySelector("[data-detail-kpi-online]");
      var downEl = kpiRow.querySelector("[data-detail-kpi-download]");
      var upEl = kpiRow.querySelector("[data-detail-kpi-upload]");
      var ispsEl = kpiRow.querySelector("[data-detail-kpi-isps]");
      if (onlineEl) {
        onlineEl.textContent =
          summary.online_clients != null ? String(summary.online_clients) : "0";
      }
      if (downEl) downEl.textContent = summary.download_label || "—";
      if (upEl) upEl.textContent = summary.upload_label || "—";
      if (ispsEl) ispsEl.textContent = String(isps.length || 0);
      setHidden(kpiRow, false);
    }

    if (grid) {
      if (!isps.length) {
        grid.innerHTML = "";
        setHidden(grid, true);
        setHidden(emptyEl, false);
        return;
      }
      grid.innerHTML = isps.map(renderIspCard).join("");
      setHidden(grid, false);
      setHidden(emptyEl, true);
    }
  }

  function applyAnalytics(data) {
    if (!data) return;
    paintHealthTrend(data.health_trend || {});
    renderHealthDrops(data.health_drops || {});
    renderInternetSetup(data.internet_setup || {});
    renderInternetAnalytics(data.internet_analytics || {});
  }

  function readLiveStatus() {
    var liveRoot = document.getElementById("mikrotik-live");
    if (!liveRoot || suspended) return { status: "", error: "" };
    if (liveRoot.classList.contains("is-online")) {
      return { status: "connected", error: "" };
    }
    if (liveRoot.classList.contains("is-offline")) {
      var blockedText = document.getElementById("mikrotik-live-blocked-text");
      var err = blockedText ? (blockedText.textContent || "").trim() : "";
      if (/password|login|credentials/i.test(err)) {
        return { status: "auth_failed", error: err };
      }
      return { status: "disconnected", error: err };
    }
    return { status: lastLiveStatus, error: lastLiveError };
  }

  function fetchAnalytics(force) {
    if (!analyticsUrl || inFlight || suspended) return;
    inFlight = true;
    var live = readLiveStatus();
    lastLiveStatus = live.status;
    lastLiveError = live.error;
    var url = analyticsUrl;
    var qs = [];
    if (force) qs.push("refresh=1");
    if (live.status) {
      qs.push("live_status=" + encodeURIComponent(live.status));
      if (live.error) qs.push("live_error=" + encodeURIComponent(live.error));
    }
    if (qs.length) url += (url.indexOf("?") >= 0 ? "&" : "?") + qs.join("&");

    fetch(url, {
      headers: { Accept: "application/json", "X-Requested-With": "XMLHttpRequest" },
      credentials: "same-origin",
    })
      .then(function (res) {
        return res.json();
      })
      .then(function (data) {
        applyAnalytics(data);
      })
      .catch(function () {
        var errEl = root.querySelector("[data-detail-analytics-error]");
        if (errEl) {
          errEl.textContent = "Could not refresh analytics.";
          setHidden(errEl, false);
        }
      })
      .finally(function () {
        inFlight = false;
      });
  }

  if (initialAnalytics) {
    applyAnalytics(initialAnalytics);
  }

  if (!suspended) {
    fetchAnalytics(false);
    pollTimer = setInterval(function () {
      fetchAnalytics(false);
    }, pollMs);
    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) fetchAnalytics(false);
    });
    window.addEventListener("beforeunload", function () {
      if (pollTimer) clearInterval(pollTimer);
    });
  }
})();
