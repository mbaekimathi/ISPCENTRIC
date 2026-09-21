(function (global) {
  "use strict";

  var labels = {
    credentials: "Updating credentials",
    wifi: "Updating Wi‑Fi",
    clean_uplink: "Applying clean uplink",
    port_toggle: "Updating port",
    port_role: "Syncing WAN port",
    uplink_bond: "Applying bond uplink",
    uplink_failover: "Applying failover uplink",
    uplink_balance: "Applying load balance",
    uplink_smart_balance: "Applying smart balance",
    pppoe_push: "Pushing PPPoE policy",
    hotspot_push: "Pushing Hotspot policy",
    nas_refresh: "Applying billing settings",
  };

  var phaseText = {
    queued: "Queued — waiting for background worker…",
    start: "Starting background push…",
    prepare: "Preparing uplink on the MikroTik…",
    unbridge: "Moving ISP cables off the LAN bridge…",
    reconnect: "Waiting for management API (brief flap is normal)…",
    configure: "Configuring uplink on the MikroTik…",
    gateways: "Waiting for ISP gateways on WAN ports…",
    bond_wan: "Starting WAN on the bond interface…",
    retire_members: "Retiring old member DHCP clients…",
    pcc: "Installing share + failover routes…",
    smart_monitor: "Installing slow-link monitor…",
    working: "Still applying — keep this page open…",
    push: "Pushing PPPoE / Hotspot billing rules to the MikroTik…",
    verify: "Verifying MikroTik management access…",
    done: "Finishing up…",
  };

  var phaseRank = {
    queued: 0,
    start: 10,
    prepare: 20,
    unbridge: 25,
    reconnect: 30,
    configure: 40,
    gateways: 45,
    bond_wan: 50,
    retire_members: 55,
    pcc: 60,
    smart_monitor: 70,
    push: 80,
    verify: 90,
    working: 95,
    done: 100,
    failed: 100,
  };

  var uplinkJobSteps = {
    uplink_smart_balance: [
      { phase: "start", label: "Start background apply" },
      { phase: "prepare", label: "Prepare MikroTik ports" },
      { phase: "unbridge", label: "Move WAN ports off LAN bridge", optional: true },
      { phase: "reconnect", label: "Reconnect management API", optional: true },
      { phase: "configure", label: "Configure WAN on each port" },
      { phase: "gateways", label: "Learn ISP gateways" },
      { phase: "pcc", label: "Install share + failover routes" },
      { phase: "smart_monitor", label: "Install slow-link monitor" },
      { phase: "done", label: "Apply complete" },
    ],
    uplink_balance: [
      { phase: "start", label: "Start background apply" },
      { phase: "prepare", label: "Prepare MikroTik ports" },
      { phase: "unbridge", label: "Move WAN ports off LAN bridge", optional: true },
      { phase: "reconnect", label: "Reconnect management API", optional: true },
      { phase: "configure", label: "Configure WAN on each port" },
      { phase: "gateways", label: "Learn ISP gateways" },
      { phase: "pcc", label: "Install share + failover routes" },
      { phase: "done", label: "Apply complete" },
    ],
    uplink_failover: [
      { phase: "start", label: "Start background apply" },
      { phase: "prepare", label: "Prepare MikroTik ports" },
      { phase: "unbridge", label: "Move WAN ports off LAN bridge", optional: true },
      { phase: "reconnect", label: "Reconnect management API", optional: true },
      { phase: "configure", label: "Configure primary + backup WAN" },
      { phase: "done", label: "Apply complete" },
    ],
    uplink_bond: [
      { phase: "start", label: "Start background apply" },
      { phase: "prepare", label: "Prepare bond members" },
      { phase: "unbridge", label: "Move WAN ports off LAN bridge", optional: true },
      { phase: "reconnect", label: "Reconnect management API", optional: true },
      { phase: "configure", label: "Create bond interface" },
      { phase: "bond_wan", label: "Start WAN on bond" },
      { phase: "retire_members", label: "Retire member DHCP clients" },
      { phase: "done", label: "Apply complete" },
    ],
    clean_uplink: [
      { phase: "start", label: "Start background apply" },
      { phase: "prepare", label: "Prepare clean uplink" },
      { phase: "configure", label: "Configure MikroTik" },
      { phase: "verify", label: "Verify management access" },
      { phase: "done", label: "Apply complete" },
    ],
  };

  function watchJobProgress(options) {
    options = options || {};
    var jobType = (options.jobType || "").trim();
    if (!jobType) return null;

    var statusUrl =
      (options.statusUrl || "").trim() ||
      (options.statusUrlBase || "").replace(/\?$/, "") +
        "?job=" +
        encodeURIComponent(jobType);
    var recoverUrl = statusUrl + (statusUrl.indexOf("?") >= 0 ? "&" : "?") + "recover=1";

    var banner = document.querySelector("[data-mikrotik-job-banner]");
    var titleEl = document.querySelector("[data-mikrotik-job-title]");
    var textEl = document.querySelector("[data-mikrotik-job-text]");
    var progressRoot = document.querySelector("[data-mikrotik-job-progress]");
    var progressTitle = document.querySelector("[data-mikrotik-job-progress-title]");
    var progressSub = document.querySelector("[data-mikrotik-job-progress-sub]");
    var progressSteps = document.querySelector("[data-mikrotik-job-steps]");
    var progressDetail = document.querySelector("[data-mikrotik-job-progress-detail]");
    var progressSpinner = document.querySelector("[data-mikrotik-job-spinner]");

    var startedAt = Date.now();
    var unknownPolls = 0;
    var recoverAttempted = false;
    var maxWaitMs =
      options.maxWaitMs ||
      (jobType.indexOf("uplink_") === 0 || jobType === "clean_uplink" ? 600000 : 240000);
    var useProgressModal =
      options.useModal !== false && !!uplinkJobSteps[jobType] && progressRoot && progressSteps;
    var seenPhases = {};
    var maxPhaseRank = 0;
    var stopped = false;

    function jobLabel() {
      return labels[jobType] || "MikroTik update";
    }

    function rankForPhase(phase) {
      var key = (phase || "").toLowerCase();
      if (key === "working") return maxPhaseRank || phaseRank.working;
      return phaseRank[key] != null ? phaseRank[key] : maxPhaseRank;
    }

    function rememberPhase(phase) {
      var key = (phase || "").toLowerCase();
      if (!key) return;
      seenPhases[key] = true;
      var rank = rankForPhase(key);
      if (rank > maxPhaseRank && key !== "failed") maxPhaseRank = rank;
    }

    function stepRank(step) {
      return phaseRank[(step.phase || "").toLowerCase()] != null
        ? phaseRank[(step.phase || "").toLowerCase()]
        : 0;
    }

    function renderProgressSteps(steps, job, status) {
      if (!useProgressModal || !progressSteps) return;
      var phase = (job.phase || "").toLowerCase();
      rememberPhase(phase);
      var currentRank = rankForPhase(phase);
      if (status === "ok") currentRank = phaseRank.done;
      if (status === "failed") currentRank = Math.max(currentRank, maxPhaseRank);

      progressSteps.innerHTML = "";
      steps.forEach(function (step) {
        var rank = stepRank(step);
        var li = document.createElement("li");
        li.className = "mk-job-progress-step";
        var state = "pending";
        if (status === "ok") {
          state = "done";
        } else if (rank < currentRank) {
          state = step.optional && !seenPhases[step.phase] ? "skipped" : "done";
        } else if (rank === currentRank) {
          if (status === "failed") state = "failed";
          else state = "active";
        } else if (step.optional && currentRank > rank + 5 && !seenPhases[step.phase]) {
          state = "skipped";
        }
        li.classList.add("is-" + state);

        var icon = document.createElement("span");
        icon.className = "mk-job-progress-step-icon";
        icon.setAttribute("aria-hidden", "true");
        if (state === "done") icon.textContent = "✓";
        else if (state === "skipped") icon.textContent = "–";
        else if (state === "failed") icon.textContent = "!";
        else if (state === "active")
          icon.innerHTML = '<span class="mk-job-progress-dot"></span>';

        var label = document.createElement("span");
        label.className = "mk-job-progress-step-label";
        label.textContent = step.label;
        li.appendChild(icon);
        li.appendChild(label);
        progressSteps.appendChild(li);
      });
    }

    function setBanner(kind, title, text) {
      if (!banner || !textEl) return;
      if (useProgressModal) {
        banner.hidden = true;
        return;
      }
      banner.hidden = false;
      banner.classList.remove("is-info", "is-success", "is-danger", "is-warn");
      banner.classList.add(kind);
      if (titleEl) titleEl.textContent = title;
      textEl.textContent = text;
    }

    function setProgress(kind, title, text, job, status) {
      if (!useProgressModal || !progressRoot) {
        setBanner(kind, title, text);
        return;
      }
      if (banner) banner.hidden = true;
      progressRoot.hidden = false;
      progressRoot.classList.remove("is-info", "is-success", "is-danger", "is-warn");
      progressRoot.classList.add(kind);
      if (progressTitle) progressTitle.textContent = title;
      if (progressSub) {
        progressSub.textContent =
          status === "ok"
            ? "Settings are live on the MikroTik."
            : status === "failed"
              ? "Apply did not finish — see details below."
              : "Working in the background — brief management flaps are normal.";
      }
      if (progressDetail) progressDetail.textContent = text || "";
      if (progressSpinner) progressSpinner.hidden = status === "ok" || status === "failed";
      renderProgressSteps(uplinkJobSteps[jobType], job || {}, status || "running");
    }

    function jobDetail(job) {
      var phase = (job.phase || "").toLowerCase();
      if (job.message) return job.message;
      if (phase && phaseText[phase]) return phaseText[phase];
      return "Working over the billing tunnel — brief management flaps are normal for uplink changes.";
    }

    function poll(recover) {
      if (stopped) return;
      var url = recover ? recoverUrl : statusUrl;
      fetch(url, {
        headers: { Accept: "application/json", "X-Requested-With": "XMLHttpRequest" },
        credentials: "same-origin",
      })
        .then(function (res) {
          return res.json();
        })
        .then(function (data) {
          if (stopped) return;
          var job = (data && data.job) || {};
          var status = (job.status || "").toLowerCase();
          var label = jobLabel();
          var elapsedMs = Date.now() - startedAt;

          if (status === "unknown") {
            unknownPolls += 1;
            if (!recoverAttempted && unknownPolls >= 3) {
              recoverAttempted = true;
              setProgress(
                "is-warn",
                label + "…",
                "Job status was lost — waiting for background worker…",
                job,
                "running"
              );
              window.setTimeout(function () {
                poll(true);
              }, 800);
              return;
            }
            setProgress(
              "is-warn",
              label + "…",
              unknownPolls < 3
                ? "Waiting for background push to register…"
                : "Still waiting for job status. Check that the Django server is running.",
              job,
              "running"
            );
            if (elapsedMs < maxWaitMs) {
              window.setTimeout(function () {
                poll(false);
              }, 2000);
            }
            return;
          }

          if (status === "pending" || status === "running") {
            setProgress("is-info", label + "…", jobDetail(job), job, "running");
            if (elapsedMs < maxWaitMs) {
              window.setTimeout(function () {
                poll(false);
              }, 2000);
            }
            return;
          }

          if (status === "ok") {
            setProgress(
              "is-success",
              label + " complete",
              job.message || "Settings applied on the MikroTik.",
              job,
              "ok"
            );
            if (typeof options.onComplete === "function") options.onComplete(job);
            if (useProgressModal) {
              window.setTimeout(function () {
                if (progressRoot) progressRoot.hidden = true;
              }, 4500);
            }
            return;
          }

          if (status === "failed") {
            var detail = job.error || "Could not apply settings on the MikroTik.";
            if (job.hint && detail.indexOf(job.hint) < 0) detail = detail + " " + job.hint;
            setProgress("is-danger", label + " failed", detail, job, "failed");
            if (typeof options.onFail === "function") options.onFail(job);
            if (typeof global.showToast === "function") {
              global.showToast({
                type: "error",
                title: label + " failed",
                text: detail,
                sticky: true,
              });
            }
            return;
          }

          window.setTimeout(function () {
            poll(false);
          }, 2500);
        })
        .catch(function () {
          if (stopped) return;
          setProgress(
            "is-warn",
            "Checking update status…",
            "Retrying in a few seconds.",
            {},
            "running"
          );
          window.setTimeout(function () {
            poll(false);
          }, 3000);
        });
    }

    if (useProgressModal) {
      setProgress(
        "is-info",
        jobLabel() + "…",
        options.initialMessage || "Starting background push…",
        { phase: "start" },
        "running"
      );
    } else {
      setBanner("is-info", jobLabel() + "…", options.initialMessage || "Starting background push…");
    }
    poll(false);

    return {
      stop: function () {
        stopped = true;
      },
    };
  }

  global.MikrotikJobProgress = {
    watch: watchJobProgress,
    labels: labels,
    uplinkJobSteps: uplinkJobSteps,
  };
})(window);
