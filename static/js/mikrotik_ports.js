(function () {
  var root = document.getElementById("mikrotik-ports-root");
  if (!root) return;
  var liveUrl = root.getAttribute("data-ports-live-url") || "";
  var csrf = root.getAttribute("data-csrf-token") || "";
  var suspended = root.getAttribute("data-is-suspended") === "1";
  var loading = root.getAttribute("data-ports-loading") === "1";
  var routerId = root.getAttribute("data-router-id") || "";
  var routerDetailUrl = root.getAttribute("data-router-detail-url") || "";
  var selectedGoal = "";
  var lastPortsData = null;
  var pendingUplinkPrompt = null;
  var pendingUplinkForm = null;
  var pendingBackupPrompt = null;
  var pendingFormRisk = null;
  var riskDialogOpen = false;
  var wanRecoveryStorageKey = "mk-wan-recovery:" + routerId;
  var wanSwitchPendingKey = "mk-wan-switch-pending:" + routerId;
  var defaultApiScriptEl = root.querySelector("[data-api-terminal-script]");
  var defaultApiScript = defaultApiScriptEl ? defaultApiScriptEl.value.trim() : "";
  var lastConnectOk = null;

  function rememberWanSwitchAttempt(newPort, script, oldPort) {
    try {
      sessionStorage.setItem(
        wanSwitchPendingKey,
        JSON.stringify({
          port: newPort || "",
          old_port: oldPort || "",
          at: Date.now(),
        })
      );
      if (script) sessionStorage.setItem(wanRecoveryStorageKey, script);
    } catch (e) {
      /* ignore */
    }
  }

  function rollbackScriptFromRisk(risk) {
    if (!risk) return "";
    return (
      risk.rollback_recovery_script ||
      risk.recovery_script ||
      ""
    );
  }

  function storePendingWanSwitch(newPort, oldPort, script) {
    if (!newPort || !oldPort || newPort === oldPort) return;
    rememberWanSwitchAttempt(newPort, script, oldPort);
  }

  function wanRollbackFromData(data) {
    if (!data || !data.wan_rollback) return null;
    var rb = data.wan_rollback;
    if (!rb.rollback_script) return null;
    return rb;
  }

  function clearWanSwitchAttempt() {
    try {
      sessionStorage.removeItem(wanSwitchPendingKey);
    } catch (e) {
      /* ignore */
    }
  }

  function readStoredWanRecoveryScript() {
    try {
      return sessionStorage.getItem(wanRecoveryStorageKey) || "";
    } catch (e) {
      return "";
    }
  }

  function riskNeedsConfirm(risk) {
    if (!risk || risk.safe || risk.blocking) return false;
    if (risk.confirmable || risk.needs_tunnel) return true;
    return !!(risk.risks && risk.risks.length);
  }

  function syncRiskProceedButton(risk, form) {
    var proceed = root.querySelector("[data-uplink-risk-proceed]");
    var checkbox = root.querySelector("[data-uplink-risk-checkbox]");
    if (!proceed || !risk) return;
    if (risk.blocking) {
      proceed.textContent = "Cannot continue";
      proceed.disabled = true;
      return;
    }
    if (form && form.classList.contains("mk-role-form")) {
      proceed.textContent = "Set Internet port";
    } else {
      proceed.textContent = form ? "Continue and apply" : "Switch Internet port";
    }
    var needConfirm = riskNeedsConfirm(risk);
    proceed.disabled = needConfirm && (!checkbox || !checkbox.checked);
  }

  function copyTextToClipboard(text, button) {
    if (!text) return;
    function done(ok) {
      if (!button) return;
      var prev = button.textContent;
      button.textContent = ok ? "Copied" : "Copy failed";
      window.setTimeout(function () {
        button.textContent = prev;
      }, 1600);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); }).catch(function () { done(false); });
      return;
    }
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.left = "-9999px";
    document.body.appendChild(area);
    area.select();
    try {
      done(document.execCommand("copy"));
    } catch (e) {
      done(false);
    }
    document.body.removeChild(area);
  }

  function setWanRecoveryScript(script) {
    var inlinePre = root.querySelector("[data-wan-recovery-script]");
    var modalPre = root.querySelector("[data-wan-recovery-modal-script]");
    var wrap = root.querySelector("[data-wan-recovery-wrap]");
    if (inlinePre) inlinePre.textContent = script || "";
    if (modalPre) modalPre.textContent = script || "";
    if (wrap) setHidden(wrap, !script);
  }

  function openWanRecoveryModal(script, oldPort, newPort) {
    var text = script || readStoredWanRecoveryScript();
    if (!text) return;
    setWanRecoveryScript(text);
    var lead = root.querySelector("[data-wan-recovery-lead]");
    var title = root.querySelector("#mk-wan-recovery-title");
    if (title) {
      title.textContent = oldPort
        ? "Reset Internet to " + oldPort
        : "Router unreachable — on-site recovery";
    }
    if (lead) {
      if (oldPort && newPort) {
        lead.innerHTML =
          "The billing server lost contact after moving Internet to <strong>" +
          esc(newPort) +
          "</strong>. Use Winbox on a <strong>customer LAN port</strong>, open " +
          "<strong>New Terminal</strong>, paste the commands below, and press Enter to " +
          "restore Internet on <strong>" +
          esc(oldPort) +
          "</strong>.";
      } else if (oldPort) {
        lead.innerHTML =
          "Use Winbox on a <strong>customer LAN port</strong>, open " +
          "<strong>New Terminal</strong>, paste the commands below, and press Enter to " +
          "restore Internet on <strong>" +
          esc(oldPort) +
          "</strong>.";
      }
    }
    setHidden(root.querySelector("[data-wan-recovery-backdrop]"), false);
    setHidden(root.querySelector("[data-wan-recovery-dialog]"), false);
  }

  function closeWanRecoveryModal() {
    setHidden(root.querySelector("[data-wan-recovery-backdrop]"), true);
    setHidden(root.querySelector("[data-wan-recovery-dialog]"), true);
  }

  function showWanRollbackIfNeeded(data) {
    var rb = wanRollbackFromData(data);
    var raw = null;
    try {
      raw = sessionStorage.getItem(wanSwitchPendingKey);
    } catch (e) {
      raw = null;
    }
    var pending = null;
    if (raw) {
      try {
        pending = JSON.parse(raw);
      } catch (e) {
        pending = null;
      }
    }
    if (pending && pending.at && Date.now() - pending.at > 15 * 60 * 1000) {
      clearWanSwitchAttempt();
      pending = null;
    }
    var script = "";
    var oldPort = "";
    var newPort = "";
    if (rb) {
      script = rb.rollback_script;
      oldPort = rb.old_wan || "";
      newPort = rb.new_wan || "";
    } else if (pending && pending.old_port) {
      script = readStoredWanRecoveryScript();
      oldPort = pending.old_port || "";
      newPort = pending.port || "";
    }
    if (!script || !oldPort) return false;
    openWanRecoveryModal(script, oldPort, newPort);
    return true;
  }

  function maybeShowWanRecoveryModal(data) {
    if (showWanRollbackIfNeeded(data || {})) return;
    var raw = null;
    try {
      raw = sessionStorage.getItem(wanSwitchPendingKey);
    } catch (e) {
      raw = null;
    }
    if (!raw) return;
    var pending = null;
    try {
      pending = JSON.parse(raw);
    } catch (e) {
      pending = null;
    }
    if (!pending || (!pending.port && !pending.old_port)) return;
    if (Date.now() - (pending.at || 0) > 15 * 60 * 1000) {
      clearWanSwitchAttempt();
      return;
    }
    openWanRecoveryModal(
      readStoredWanRecoveryScript(),
      pending.old_port || "",
      pending.port || ""
    );
  }
  if (!loading || !liveUrl) return;

  var goalHints = {
    single: "One ISP cable — mark it Internet. Backup and bonding roles are hidden.",
    bond: "Two cables from the same ISP — use Detect & apply, or mark Bonded internet on each port.",
    failover: "Two or more ISPs — one Internet, one or more Backup internet, all link up, then apply.",
    balance: "Two or more ISPs sharing traffic — one Internet, rest Shared ISP, enter Mbps, then apply.",
    smart_balance: "Two or more ISPs — weighted sharing plus auto-avoid when one is slow."
  };
  var goalSelectHints = {
    single: "Move one cable between ports anytime — tap Internet on the new port.",
    bond: "Same provider: plug two cables, then Detect & apply bonding.",
    failover: "Different providers: standby ISP(s) take over when the primary fails.",
    balance: "Different providers: all carry traffic, weighted by the Mbps you enter.",
    smart_balance: "Like weighted balance, but the router sidelines slow ISPs from new connections."
  };

  var ROLE_LABELS = {
    wan: "Internet",
    wan_backup: "Backup internet",
    bond: "Bonded internet",
    lan: "Customers",
    unused: "Unused",
    none: "Unassigned"
  };

  function roleLabelsForGoal(goal) {
    var labels = Object.assign({}, ROLE_LABELS);
    if (goal === "balance" || goal === "smart_balance") {
      labels.wan_backup = "Shared ISP";
    }
    return labels;
  }

  function rolesForGoal(goal, allowedRoles) {
    var allowed = allowedRoles && allowedRoles.length
      ? allowedRoles
      : null;
    var labels = roleLabelsForGoal(goal);
    function canUse(value) {
      return !allowed || allowed.indexOf(value) >= 0;
    }
    function pair(value) {
      return [value, labels[value] || ROLE_LABELS[value] || value];
    }
    function pick(values) {
      return values.filter(canUse).map(pair);
    }

    if (goal === "bond") {
      return {
        main: pick(["bond", "lan", "unused"]),
        more: pick(["none"])
      };
    }
    if (goal === "failover" || goal === "balance" || goal === "smart_balance") {
      return {
        main: pick(["wan", "wan_backup", "lan", "unused"]),
        more: pick(["none"])
      };
    }
    return {
      main: pick(["wan", "lan", "unused"]),
      more: pick(["none"])
    };
  }

  function setSelectedGoal(goal, options) {
    var opts = options || {};
    var next = goal || "single";
    if (["single", "bond", "failover", "balance", "smart_balance"].indexOf(next) < 0) next = "single";
    selectedGoal = next;

    var select = root.querySelector("[data-uplink-goal-select]");
    if (select && select.value !== next) select.value = next;

    root.querySelectorAll("[data-goal-panel]").forEach(function (panel) {
      setHidden(panel, panel.getAttribute("data-goal-panel") !== next);
    });

    var selectHint = root.querySelector("[data-goal-select-hint]");
    if (selectHint) selectHint.textContent = goalSelectHints[next] || "";

    var hint = root.querySelector("[data-ports-assign-hint]");
    if (hint) hint.textContent = goalHints[next] || goalHints.single;

    if (!opts.skipRerender && lastPortsData && lastPortsData.ok) {
      renderPortCards(lastPortsData);
    }
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function setHidden(el, hidden) {
    if (!el) return;
    if (hidden) el.setAttribute("hidden", "");
    else el.removeAttribute("hidden");
  }

  function portByName(ports, name) {
    for (var i = 0; i < (ports || []).length; i++) {
      if (ports[i] && ports[i].name === name) return ports[i];
    }
    return null;
  }

  function portLinkState(port) {
    if (!port) return "missing";
    if (port.disabled) return "disabled";
    if (port.running) return "up";
    return "down";
  }

  function flowChip(port, opts) {
    var options = opts || {};
    var name = (port && port.name) || options.name || "";
    var role = (port && port.role) || options.role || "none";
    var link = portLinkState(port);
    var extra = options.extra || "";
    var tone = options.tone || ("role-" + role);
    var title = options.title || (port && port.role_label) || name;
    return (
      '<button type="button" class="mk-flow-chip ' + esc(tone) + " is-" + esc(link) + '"' +
      ' data-jump-port="' + esc(name) + '"' +
      ' title="' + esc(title) + '">' +
      '<span class="mk-flow-chip-led" aria-hidden="true"></span>' +
      '<span class="mk-flow-chip-name">' + esc(name) + "</span>" +
      (extra ? '<span class="mk-flow-chip-extra">' + esc(extra) + "</span>" : "") +
      "</button>"
    );
  }

  function emptyStage(text) {
    return '<p class="mk-flow-empty">' + esc(text) + "</p>";
  }

  function uplinkKindLabel(port) {
    if (!port) return "";
    if (port.uplink_kind === "pppoe") {
      return port.uplink_iface ? "PPPoE · " + port.uplink_iface : "PPPoE";
    }
    if (port.uplink_kind === "dhcp") return "DHCP";
    return "";
  }

  function portInternetBadge(port) {
    if (!port || port.is_bond_iface) return "";
    if (port.internet_verified) {
      return '<span class="mk-port-inet is-ok" title="ISP internet verified">ISP online</span>';
    }
    var hint = (port.internet_hint || "").trim();
    if (!hint) return "";
    var level = (port.internet_level || "warn").toLowerCase();
    var cls = level === "block" ? "is-block" : "is-warn";
    return (
      '<span class="mk-port-inet ' +
      cls +
      '" title="' +
      esc(hint) +
      '">' +
      esc(level === "block" ? "No ISP" : "ISP pending") +
      "</span>"
    );
  }

  function routerName() {
    var el = root.querySelector("[data-router-name]");
    return (el && el.textContent.trim()) || "MikroTik";
  }

  function renderFlow(data) {
    var map = root.querySelector("[data-ports-map]");
    var internetEl = root.querySelector("[data-flow-internet]");
    var routerEl = root.querySelector("[data-flow-router]");
    var customersEl = root.querySelector("[data-flow-customers]");
    var wanConn = root.querySelector('[data-flow-connector="wan"]');
    var lanConn = root.querySelector('[data-flow-connector="lan"]');
    if (!map || !internetEl || !routerEl || !customersEl) return;

    var ports = data.ports || [];
    var physical = data.physical_ports || [];
    if (!physical.length) {
      setHidden(map, true);
      return;
    }
    setHidden(map, false);

    var mode = data.uplink_mode || "single";
    var primary = data.primary_wan_ports || [];
    var bond = data.bond_member_ports || [];
    var backups = data.backup_wan_ports || [];
    var lan = data.lan_ports || [];
    var unused = data.unused_ports || [];
    var live = data.uplink_live || {};

    var internetHtml = "";
    var wanLive = false;
    var failoverOnBackup = false;

    if (mode === "bond" && bond.length) {
      internetHtml += '<div class="mk-flow-group is-bond">';
      internetHtml += '<span class="mk-flow-group-label">Bonded uplink</span>';
      internetHtml += '<div class="mk-flow-chip-row">';
      bond.forEach(function (name) {
        var p = portByName(ports, name);
        if (portLinkState(p) === "up") wanLive = true;
        internetHtml += flowChip(p, {
          name: name,
          role: "bond",
          tone: "role-bond",
          extra: uplinkKindLabel(p) || "Bond member",
          title: "Bonded internet · " + name
        });
      });
      internetHtml += "</div>";
      if (data.bond_interface) {
        internetHtml +=
          '<div class="mk-flow-merge">' +
          '<span class="mk-flow-merge-line" aria-hidden="true"></span>' +
          '<span class="mk-flow-merge-label">' +
          esc(data.bond_interface) +
          (data.bond_mode ? " · " + esc(data.bond_mode) : "") +
          "</span></div>";
      }
      internetHtml += "</div>";
    } else if ((mode === "balance" || mode === "smart_balance") && (primary.length || backups.length)) {
      var balanceMembers = primary.concat(backups);
      var shareMap = {};
      ((data.wan_share && data.wan_share.shares) || []).forEach(function (s) {
        if (s && s.name) shareMap[s.name] = s;
      });
      var shareParts = balanceMembers.map(function (name) {
        var s = shareMap[name];
        return s && s.pct != null ? String(s.pct) + "%" : "—";
      });
      var shareKnown = shareParts.every(function (p) { return p !== "—"; });
      var shareTotal = balanceMembers.reduce(function (sum, name) {
        var s = shareMap[name] || {};
        return sum + (parseInt(s.pct, 10) || 0);
      }, 0);
      internetHtml += '<div class="mk-flow-group is-balance">';
      internetHtml +=
        '<span class="mk-flow-group-label is-working">Sharing ' +
        esc(
          shareKnown
            ? shareTotal > 0
              ? shareParts.join(" / ")
              : "idle · " + shareParts.join(" / ")
            : shareParts.join(" / ")
        ) +
        "</span>";
      internetHtml += '<div class="mk-flow-share-bars" aria-hidden="true">';
      balanceMembers.forEach(function (name) {
        var s = shareMap[name] || {};
        var pct = Math.max(0, Math.min(100, parseInt(s.pct, 10) || 0));
        var flex = shareKnown && shareTotal > 0 ? Math.max(pct, 1) : 1;
        internetHtml +=
          '<span class="mk-flow-share-seg" style="flex:' +
          flex +
          '" title="' +
          esc(name + ": " + (s.pct != null ? s.pct + "%" : "—")) +
          '"></span>';
      });
      internetHtml += "</div>";
      internetHtml += '<div class="mk-flow-chip-row is-active-row">';
      balanceMembers.forEach(function (name) {
        var p = portByName(ports, name);
        var s = shareMap[name] || {};
        var pct = typeof s.pct === "number" ? s.pct : parseInt(s.pct, 10);
        if (isNaN(pct)) pct = null;
        if (portLinkState(p) === "up") wanLive = true;
        var kindLabel = uplinkKindLabel(p);
        var extra;
        if (pct != null) {
          extra = pct + "%";
          if (s.rate_label && s.rate_label !== "—") {
            extra += " · " + s.rate_label;
          } else if (s.bytes_label && s.bytes_label !== "0 B") {
            extra += " · " + s.bytes_label;
          }
        } else {
          extra = portLinkState(p) === "up" ? "Sharing" : "Down";
        }
        if (kindLabel && pct == null) extra = kindLabel + " · " + extra;
        internetHtml += flowChip(p, {
          name: name,
          role: primary.indexOf(name) >= 0 ? "wan" : "wan_backup",
          tone: portLinkState(p) === "up" ? "is-active-path" : "role-wan is-failed",
          extra: extra,
          title:
            "Load-balanced WAN · " +
            name +
            (pct != null ? " · " + pct + "% of traffic" : "")
        });
      });
      internetHtml += "</div></div>";
    } else if (mode === "failover" && (primary.length || backups.length)) {
      var primaryUp = primary.filter(function (name) {
        return portLinkState(portByName(ports, name)) === "up";
      });
      var backupUp = backups.filter(function (name) {
        return portLinkState(portByName(ports, name)) === "up";
      });
      // Prefer RouterOS active default route (by distance → client interface),
      // else fall back to which WAN/backup port has link up.
      var activeNames = [];
      var activeRoute = (live.checked_routes || []).filter(function (r) {
        return r && r.active && !r.disabled;
      })[0];
      if (activeRoute) {
        var dist = String(activeRoute.distance || "1");
        (live.failover_clients || []).forEach(function (c) {
          if (!c || c.disabled) return;
          if (String(c.distance || "1") !== dist) return;
          var iface = (c.interface || "").trim();
          if (iface && activeNames.indexOf(iface) < 0) activeNames.push(iface);
        });
      }
      if (!activeNames.length) {
        if (primaryUp.length) activeNames = primaryUp.slice();
        else if (backupUp.length) activeNames = backupUp.slice(0, 1);
      }
      // Keep only ports that are part of this failover set.
      activeNames = activeNames.filter(function (n) {
        return primary.indexOf(n) >= 0 || backups.indexOf(n) >= 0;
      });
      if (!activeNames.length) {
        if (primaryUp.length) activeNames = primaryUp.slice();
        else if (backupUp.length) activeNames = backupUp.slice(0, 1);
      }
      var activeSet = {};
      activeNames.forEach(function (n) { activeSet[n] = true; });
      failoverOnBackup = activeNames.some(function (n) {
        return backups.indexOf(n) >= 0;
      });
      wanLive = activeNames.length > 0;

      function renderFailoverChip(name, kind) {
        var p = portByName(ports, name);
        var isActive = !!activeSet[name];
        var kindLabel = uplinkKindLabel(p);
        if (isActive) {
          return flowChip(p, {
            name: name,
            role: kind === "primary" ? "wan" : "wan_backup",
            tone: "is-active-path",
            extra: (kindLabel ? kindLabel + " · " : "") + "Working now",
            title: (failoverOnBackup && kind === "backup" ? "Backup carrying traffic · " : "Active internet · ") + name
          });
        }
        if (kind === "primary") {
          return flowChip(p, {
            name: name,
            role: "wan",
            tone: "role-wan is-primary is-failed",
            extra: (kindLabel ? kindLabel + " · " : "") + "Primary down",
            title: "Primary offline · " + name
          });
        }
        return flowChip(p, {
          name: name,
          role: "wan_backup",
          tone: "role-wan_backup is-backup is-standby",
          extra: (kindLabel ? kindLabel + " · " : "") + "Standby",
          title: "Backup standby · " + name
        });
      }

      var standbyPrimary = primary.filter(function (name) { return !activeSet[name]; });
      var standbyBackup = backups.filter(function (name) { return !activeSet[name]; });
      var parts = ['<div class="mk-flow-group is-failover' + (failoverOnBackup ? " is-on-backup" : "") + '">'];

      if (wanLive) {
        parts.push('<span class="mk-flow-group-label is-working">Working now</span>');
        parts.push('<div class="mk-flow-chip-row is-active-row">');
        activeNames.forEach(function (name) {
          var kind = primary.indexOf(name) >= 0 ? "primary" : "backup";
          parts.push(renderFailoverChip(name, kind));
        });
        parts.push("</div>");
      } else {
        parts.push('<span class="mk-flow-group-label is-failed">No link up</span>');
      }

      if (standbyPrimary.length || standbyBackup.length) {
        parts.push(
          '<span class="mk-flow-group-label' +
            (failoverOnBackup || !wanLive ? " is-failed" : " is-backup") +
            '">' +
            (failoverOnBackup
              ? "Primary failed — waiting"
              : wanLive
                ? "Backup standby"
                : "Assigned ports") +
            "</span>"
        );
        parts.push('<div class="mk-flow-chip-row is-dashed">');
        standbyPrimary.forEach(function (name) {
          parts.push(renderFailoverChip(name, "primary"));
        });
        standbyBackup.forEach(function (name) {
          parts.push(renderFailoverChip(name, "backup"));
        });
        parts.push("</div>");
      }

      parts.push("</div>");
      internetHtml = parts.join("");
    } else if (primary.length) {
      internetHtml += '<div class="mk-flow-chip-row">';
      primary.forEach(function (name) {
        var p = portByName(ports, name);
        if (portLinkState(p) === "up") wanLive = true;
        internetHtml += flowChip(p, {
          name: name,
          role: "wan",
          tone: "role-wan",
          extra: uplinkKindLabel(p) || "WAN",
          title: "Internet · " + name
        });
      });
      internetHtml += "</div>";
    } else {
      internetHtml = emptyStage("Not assigned yet — pick Internet on a port card");
    }
    internetEl.innerHTML = internetHtml;

    var modeLabel = data.uplink_mode_label || "Single WAN";
    var health = "";
    if (mode === "bond") {
      var bondLive = (live.bonds || [])[0];
      if (bondLive && bondLive.running) {
        health = "Bond up";
        wanLive = true;
      } else if (bond.length) {
        health = "Bond waiting";
      }
    } else if (mode === "balance" || mode === "smart_balance") {
      var balanceCount = primary.length + backups.length;
      var slowPorts = ((data.smart_balance_status && data.smart_balance_status.slow_ports) || []);
      var shareBits = ((data.wan_share && data.wan_share.shares) || [])
        .map(function (s) {
          return (s.name || "?") + " " + (s.pct != null ? s.pct + "%" : "—");
        })
        .join(" · ");
      if (!data.balance_router_applied) {
        health = data.can_apply_balance || data.can_apply_smart_balance
          ? (mode === "smart_balance" ? "Configured — applying smart balance…" : "Configured — click Apply load balance")
          : (mode === "smart_balance" ? "Smart balance setup — waiting for links" : "Balance setup — not on MikroTik yet");
      } else if (mode === "smart_balance" && !data.smart_balance_applied) {
        health = "PCC active — installing slow-link monitor…";
      } else if (slowPorts.length && mode === "smart_balance") {
        health = "Slow ISP sidelined: " + slowPorts.join(", ");
      } else if (shareBits) {
        health = "Live share · " + shareBits;
      } else if (wanLive) {
        health =
          (balanceCount >= 2 ? balanceCount + " ISPs" : "ISPs") +
          (mode === "smart_balance"
            ? (data.smart_balance_applied ? " smart-sharing + monitor" : " smart-sharing (PCC)")
            : " sharing traffic (PCC)");
      } else {
        health = "Balance configured · waiting for links";
      }
    } else if (mode === "failover") {
      var checked = live.checked_routes || [];
      var active = checked.filter(function (r) { return r.active; })[0];
      if (failoverOnBackup) {
        health = active
          ? "Backup carrying traffic via " + (active.gateway || "gateway")
          : "Backup carrying traffic (primary down)";
      } else if (active) {
        health = "Active via " + (active.gateway || "gateway");
      } else if (checked.length) {
        health = "Waiting for gateway check";
      } else if (wanLive) {
        health = "Primary link up";
      } else {
        health = "Failover ready";
      }
    } else if (wanLive) {
      health = "Link up";
    } else if (primary.length) {
      health = "No link on WAN";
    } else {
      health = "Assign a WAN port";
    }

    routerEl.innerHTML =
      '<div class="mk-flow-router-card' + (wanLive ? " is-live" : "") + '">' +
      '<strong class="mk-flow-router-name">' + esc(routerName()) + "</strong>" +
      '<span class="mk-flow-router-mode">' + esc(modeLabel) + "</span>" +
      (health ? '<span class="mk-flow-router-health">' + esc(health) + "</span>" : "") +
      "</div>";

    var customersHtml = "";
    if (lan.length) {
      customersHtml += '<div class="mk-flow-chip-row">';
      lan.forEach(function (name) {
        var p = portByName(ports, name);
        customersHtml += flowChip(p, {
          name: name,
          role: "lan",
          tone: "role-lan",
          extra: "Customers",
          title: "Customers · " + name
        });
      });
      customersHtml += "</div>";
    } else {
      customersHtml = emptyStage("No customer ports yet");
    }
    if (unused.length) {
      customersHtml += '<div class="mk-flow-parked">';
      customersHtml += '<span class="mk-flow-group-label">Parked / unused</span>';
      customersHtml += '<div class="mk-flow-chip-row">';
      unused.forEach(function (name) {
        var p = portByName(ports, name);
        customersHtml += flowChip(p, {
          name: name,
          role: "unused",
          tone: "role-unused",
          extra: "Unused",
          title: "Unused · " + name
        });
      });
      customersHtml += "</div></div>";
    }
    customersEl.innerHTML = customersHtml;

    if (wanConn) {
      wanConn.classList.toggle("is-live", wanLive);
      wanConn.classList.toggle("is-dashed", mode === "failover" && !failoverOnBackup && !wanLive);
      wanConn.classList.toggle("is-bond", mode === "bond");
      wanConn.classList.toggle("is-on-backup", failoverOnBackup);
      wanConn.classList.toggle("is-balance", (mode === "balance" || mode === "smart_balance") && wanLive);
    }
    if (lanConn) {
      lanConn.classList.toggle("is-live", lan.some(function (name) {
        return portLinkState(portByName(ports, name)) === "up";
      }));
    }
  }

  function renderFace(data) {
    var face = root.querySelector("[data-ports-face]");
    var map = root.querySelector("[data-ports-map]");
    if (!face) return;
    var physical = data.physical_ports || [];
    if (!physical.length) {
      face.innerHTML = "";
      return;
    }
    face.innerHTML = physical.map(function (port) {
      var role = port.role || "none";
      var link = portLinkState(port);
      var label = port.role_label || role;
      return (
        '<button type="button" class="mk-port-jack role-' + esc(role) + " is-" + esc(link) + '"' +
        ' data-jump-port="' + esc(port.name) + '"' +
        ' role="listitem"' +
        ' title="' + esc(port.name + " · " + label) + '"' +
        ' aria-label="' + esc(port.name + ", " + label + ", link " + link) + '">' +
        '<span class="mk-port-jack-shell" aria-hidden="true">' +
        '<span class="mk-port-jack-slot"></span>' +
        '<span class="mk-port-jack-led"></span>' +
        "</span>" +
        '<span class="mk-port-jack-name">' + esc(port.name) + "</span>" +
        '<span class="mk-port-jack-role">' + esc(label) + "</span>" +
        "</button>"
      );
    }).join("");
    if (map) setHidden(map, false);
  }

  function jumpToPortCard(portName) {
    if (!portName) return;
    var cards = root.querySelectorAll(".mk-port-card[data-port-name]");
    var card = null;
    for (var i = 0; i < cards.length; i++) {
      if (cards[i].getAttribute("data-port-name") === portName) {
        card = cards[i];
        break;
      }
    }
    if (!card) return;
    root.querySelectorAll(".mk-port-card.is-focus").forEach(function (el) {
      el.classList.remove("is-focus");
    });
    card.classList.add("is-focus");
    card.scrollIntoView({ behavior: "smooth", block: "center" });
    window.setTimeout(function () { card.classList.remove("is-focus"); }, 1800);
  }

  function chipList(ul, names, chipClass, ports) {
    if (!ul) return;
    var byName = {};
    (ports || []).forEach(function (p) {
      if (p && p.name) byName[p.name] = p;
    });
    ul.innerHTML = "";
    (names || []).forEach(function (name) {
      var li = document.createElement("li");
      var p = byName[name];
      var sub = "";
      if (p) {
        if (p.disabled) sub = "disabled";
        else if (p.running) sub = "link up";
        else sub = "no link";
      }
      li.innerHTML =
        '<span class="mk-chip' +
        (chipClass ? " " + chipClass : "") +
        '">' +
        esc(name) +
        (sub ? '<span class="mk-chip-sub">' + esc(sub) + "</span>" : "") +
        "</span>";
      ul.appendChild(li);
    });
  }

  function gcdTwo(a, b) {
    a = Math.abs(a);
    b = Math.abs(b);
    while (b) {
      var t = b;
      b = a % b;
      a = t;
    }
    return a || 1;
  }

  function balanceSharePreview(weights) {
    var vals = (weights || []).map(function (w) {
      return Math.max(1, parseInt(w, 10) || 1);
    });
    if (vals.length < 2) return "";
    var g = vals.reduce(function (acc, v) { return gcdTwo(acc, v); }, vals[0]);
    var slots = vals.map(function (v) { return Math.max(1, Math.round(v / g)); });
    var total = slots.reduce(function (a, b) { return a + b; }, 0);
    var pcts = slots.map(function (s) {
      return Math.round((100 * s) / total);
    });
    return "Target share ≈ " + pcts.join("% / ") + "% (ratio " + slots.join(":") + ")";
  }

  function renderBalanceWeights(names, savedWeights, panelPrefix) {
    panelPrefix = panelPrefix || "balance";
    var wrap = root.querySelector("[data-" + panelPrefix + "-weights-wrap]");
    var box = root.querySelector("[data-" + panelPrefix + "-weights]");
    var preview = root.querySelector("[data-" + panelPrefix + "-weight-preview]");
    var preferredEl = root.querySelector("[data-" + panelPrefix + "-preferred]");
    if (!box || !wrap) return;
    var ports = names || [];
    var saved = savedWeights && typeof savedWeights === "object" ? savedWeights : {};
    setHidden(wrap, ports.length < 2);
    if (ports.length < 2) {
      box.innerHTML = "";
      if (preview) preview.textContent = "";
      if (preferredEl) {
        preferredEl.textContent = "";
        setHidden(preferredEl, true);
      }
      return;
    }

    var existing = {};
    box.querySelectorAll('input[type="number"]').forEach(function (inp) {
      var key = (inp.getAttribute("name") || "").replace(/^weight_/, "");
      if (key) existing[key] = inp.value;
    });

    box.innerHTML = ports
      .map(function (name, index) {
        var val = parseInt(existing[name], 10);
        if (!val || val < 1) val = parseInt(saved[name], 10);
        if (!val || val < 1) val = index === 0 ? 100 : 100;
        return (
          '<label class="mk-balance-weight-row">' +
          '<span class="mk-balance-weight-port">' +
          esc(name) +
          "</span>" +
          '<input type="number" name="weight_' +
          esc(name) +
          '" min="1" max="10000" step="1" value="' +
          esc(String(val)) +
          '" inputmode="numeric" required>' +
          "<span>Mbps</span></label>"
        );
      })
      .join("");

    function readWeights() {
      var rows = [];
      box.querySelectorAll('input[type="number"]').forEach(function (inp) {
        var key = (inp.getAttribute("name") || "").replace(/^weight_/, "");
        rows.push({
          name: key,
          mbps: Math.max(1, parseInt(inp.value, 10) || 1),
          input: inp
        });
      });
      return rows;
    }

    function updatePreview() {
      var rows = readWeights();
      var vals = rows.map(function (r) { return r.mbps; });
      if (preview) preview.textContent = balanceSharePreview(vals);
      if (!preferredEl) return;
      if (!rows.length) {
        preferredEl.textContent = "";
        setHidden(preferredEl, true);
        return;
      }
      var best = rows.slice().sort(function (a, b) {
        return b.mbps - a.mbps || a.name.localeCompare(b.name);
      })[0];
      preferredEl.textContent =
        "Preferred for clients: " +
        best.name +
        " (" +
        best.mbps +
        " Mbps) — gets most new connections and wins if another ISP dies.";
      setHidden(preferredEl, false);
      box.querySelectorAll(".mk-balance-weight-row").forEach(function (row) {
        row.classList.remove("is-preferred");
      });
      if (best.input && best.input.closest) {
        var row = best.input.closest(".mk-balance-weight-row");
        if (row) row.classList.add("is-preferred");
      }
    }

    box.querySelectorAll('input[type="number"]').forEach(function (inp) {
      inp.addEventListener("input", updatePreview);
    });
    updatePreview();
  }

  function applyBalancePreset(kind, panelPrefix) {
    panelPrefix = panelPrefix || "balance";
    var box = root.querySelector("[data-" + panelPrefix + "-weights]");
    if (!box) return;
    var inputs = Array.prototype.slice.call(box.querySelectorAll('input[type="number"]'));
    if (inputs.length < 2) return;
    if (kind === "equal") {
      inputs.forEach(function (inp) { inp.value = "100"; });
    } else if (kind === "prefer3" || kind === "prefer5") {
      var bestIdx = 0;
      var bestVal = 0;
      for (var i = 0; i < inputs.length; i++) {
        var val = parseInt(inputs[i].value, 10) || 0;
        if (val > bestVal) {
          bestVal = val;
          bestIdx = i;
        }
      }
      var strongBase = Math.max(bestVal, 100);
      var ratio = kind === "prefer5" ? 5 : 3;
      inputs.forEach(function (inp, idx) {
        inp.value = idx === bestIdx ? String(strongBase * ratio) : String(strongBase);
      });
    }
    inputs.forEach(function (inp) {
      inp.dispatchEvent(new Event("input", { bubbles: true }));
    });
  }

  function portSortKey(port, mode) {
    var role = (port.role || "none").toLowerCase();
    var order = {
      wan: 0,
      wan_primary: 0,
      wan_backup: 1,
      bond: 2,
      lan: 3,
      none: 4,
      unused: 5
    };
    var base = order[role] != null ? order[role] : 6;
    if (mode === "bond" && role === "bond") base = 0;
    return [base, port.name || ""];
  }

  function bridgeRoleHint(mode) {
    if (mode === "bond") return "Bonded internet";
    if (mode === "failover") return "Internet/Backup internet";
    if (mode === "balance" || mode === "smart_balance") return "Internet/Shared ISP";
    return "Internet";
  }

  function updatePortsAssignSection(data) {
    var mode = data.uplink_mode || "single";
    var hint = root.querySelector("[data-ports-assign-hint]");
    if (hint) {
      hint.textContent =
        data.ports_assign_hint || goalHints[mode] || goalHints.single;
    }
    var title = root.querySelector("[data-ports-assign-title]");
    if (title) {
      var titles = {
        single: "Label each cable",
        bond: "Bond members (auto-updated)",
        failover: "ISP ports (auto-updated)",
        balance: "ISP ports (auto-updated)",
        smart_balance: "ISP ports (auto-updated)"
      };
      title.textContent = titles[mode] || titles.single;
    }
  }

  function rolePickForms(portName, role, roles) {
    return roles.map(function (pair) {
      var value = pair[0];
      var label = pair[1];
      var active = role === value ? " is-active role-" + value : "";
      var confirmField =
        value === "wan"
          ? '<input type="hidden" name="confirm_risk" value="">'
          : "";
      return (
        '<form method="post" class="mk-role-form">' +
        '<input type="hidden" name="csrfmiddlewaretoken" value="' + esc(csrf) + '">' +
        '<input type="hidden" name="action" value="set_port_role">' +
        '<input type="hidden" name="port_name" value="' + esc(portName) + '">' +
        '<input type="hidden" name="role" value="' + esc(value) + '">' +
        confirmField +
        '<button type="submit" class="mk-role-pick' + active + '"' +
        (value === "wan" ? ' data-wan-role-pick="1"' : "") +
        (suspended ? " disabled" : "") +
        ">" + esc(label) + "</button></form>"
      );
    }).join("");
  }

  function renderPortCard(port, allowedRoles, uplinkMode) {
    var mode = uplinkMode || selectedGoal || "single";
    var role = port.role || "none";
    var pendingClass = port.role_matches_setup === false ? " is-pending-setup" : "";
    var stateClass = port.disabled ? " is-disabled" : port.running ? " is-up" : " is-down";
    var bondClass = port.is_bond_iface ? " is-bond" : "";
    var statusHtml = port.disabled
      ? '<span class="mk-status-pill is-off"><span class="mk-status-dot" aria-hidden="true"></span>Disabled</span>'
      : port.running
        ? '<span class="mk-status-pill is-on"><span class="mk-status-dot" aria-hidden="true"></span>Link up</span>'
        : '<span class="mk-status-pill is-muted"><span class="mk-status-dot" aria-hidden="true"></span>No link</span>';
    var body;
    if (port.is_bond_iface) {
      body = '<p class="mk-help-note">Bond interface — managed by multi-uplink settings.</p>';
    } else {
      var roles = rolesForGoal(mode, allowedRoles);
      var moreValues = roles.more.map(function (pair) { return pair[0]; });
      var advOpen = moreValues.indexOf(role) >= 0 ? " open" : "";
      var bridgeWarn = "";
      if (port.is_bridged) {
        bridgeWarn =
          '<p class="mk-help-note is-warn">On bridge ' +
          esc(port.bridge || "LAN") +
          " — assigning " +
          esc(bridgeRoleHint(mode)) +
          " will unbridge this port when you apply.</p>";
      }
      var suggestedHtml = "";
      if (port.suggested_role && port.suggested_role !== role && port.suggested_role_label) {
        suggestedHtml =
          '<p class="mk-help-note is-suggest">Pending: will become <strong>' +
          esc(port.suggested_role_label) +
          "</strong> when this link has ISP internet.</p>";
      }
      body =
        bridgeWarn +
        suggestedHtml +
        '<div class="mk-role-picks" role="group" aria-label="Role for ' + esc(port.name) + '">' +
        rolePickForms(port.name, role, roles.main) +
        "</div>" +
        '<details class="mk-port-more"' + advOpen + ">" +
        "<summary>More roles</summary>" +
        '<div class="mk-role-picks is-advanced">' +
        rolePickForms(port.name, role, roles.more) +
        "</div></details>";
    }
    return (
      '<article class="mk-port-card role-' + esc(role) + stateClass + bondClass + pendingClass + '"' +
      ' data-port-name="' + esc(port.name) + '" id="port-card-' + esc(port.name).replace(/[^a-zA-Z0-9_-]/g, "-") + '">' +
      '<header class="mk-port-card-head"><div>' +
      '<strong class="mk-port-name">' + esc(port.name) + "</strong>" +
      '<div class="mk-port-meta">' +
      '<span class="mk-port-type">' + esc(port.type || "") + "</span>" +
      (port.bridge ? '<span class="mk-port-bridge">on ' + esc(port.bridge) + "</span>" : "") +
      (port.uplink_kind === "pppoe"
        ? '<span class="mk-port-uplink">PPPoE' + (port.uplink_iface ? " · " + esc(port.uplink_iface) : "") + "</span>"
        : port.uplink_kind === "dhcp"
          ? '<span class="mk-port-uplink">DHCP</span>'
          : "") +
      (port.comment ? '<span class="mk-port-comment">' + esc(port.comment) + "</span>" : "") +
      portInternetBadge(port) +
      "</div></div>" + statusHtml + "</header>" +
      body +
      '<footer class="mk-port-card-foot">' +
      '<span class="mk-port-role-label">' + esc(port.role_label || role) + "</span>" +
      '<form method="post">' +
      '<input type="hidden" name="csrfmiddlewaretoken" value="' + esc(csrf) + '">' +
      '<input type="hidden" name="action" value="toggle_port">' +
      '<input type="hidden" name="port_name" value="' + esc(port.name) + '">' +
      (port.disabled
        ? '<button type="submit" class="btn btn-primary btn-sm"' + (suspended ? " disabled" : "") + ">Enable</button>"
        : '<button type="submit" class="btn btn-ghost btn-sm"' + (suspended ? " disabled" : "") + ">Disable</button>") +
      "</form></footer></article>"
    );
  }

  function renderPortCards(data) {
    var allPorts = data.ports || [];
    var allowedRoles = data.allowed_roles || [];
    var mode = data.uplink_mode || "single";
    var grid = root.querySelector("[data-ports-grid]");
    var assign = root.querySelector("[data-ports-assign]");
    if (!grid) return;
    if (allPorts.length) {
      var sorted = allPorts.slice().sort(function (a, b) {
        var ka = portSortKey(a, mode);
        var kb = portSortKey(b, mode);
        if (ka[0] !== kb[0]) return ka[0] - kb[0];
        return ka[1].localeCompare(kb[1]);
      });
      grid.innerHTML = sorted.map(function (port) {
        return renderPortCard(port, allowedRoles, mode);
      }).join("");
      setHidden(grid, false);
      setHidden(assign, false);
      setHidden(root.querySelector("[data-ports-empty]"), true);
    } else {
      setHidden(grid, true);
      setHidden(assign, true);
      setHidden(root.querySelector("[data-ports-empty]"), false);
      setHidden(root.querySelector("[data-ports-map]"), true);
    }
  }

  function backupDismissKey(port) {
    return "mk-backup-uplink-dismiss:" + routerId + ":" + (port || "");
  }

  function isBackupDismissed(port) {
    try {
      return sessionStorage.getItem(backupDismissKey(port)) === "1";
    } catch (e) {
      return false;
    }
  }

  function dismissBackupPrompt(port) {
    try {
      sessionStorage.setItem(backupDismissKey(port), "1");
    } catch (e) {
      /* ignore */
    }
    setHidden(root.querySelector("[data-backup-uplink-prompt]"), true);
    closeUplinkRiskDialog();
  }

  function uplinkDismissKey(port) {
    return "mk-uplink-dismiss:" + routerId + ":" + (port || "");
  }

  function isUplinkDismissed(port) {
    try {
      return sessionStorage.getItem(uplinkDismissKey(port)) === "1";
    } catch (e) {
      return false;
    }
  }

  function dismissUplinkPrompt(port) {
    try {
      sessionStorage.setItem(uplinkDismissKey(port), "1");
    } catch (e) {
      /* ignore */
    }
    setHidden(root.querySelector("[data-uplink-prompt]"), true);
    closeUplinkRiskDialog();
  }

  function closeUplinkRiskDialog() {
    setHidden(root.querySelector("[data-uplink-risk-backdrop]"), true);
    setHidden(root.querySelector("[data-uplink-risk-dialog]"), true);
    pendingUplinkPrompt = null;
    pendingUplinkForm = null;
    pendingBackupPrompt = null;
    pendingFormRisk = null;
    riskDialogOpen = false;
    var checkbox = root.querySelector("[data-uplink-risk-checkbox]");
    if (checkbox) checkbox.checked = false;
    var proceed = root.querySelector("[data-uplink-risk-proceed]");
    if (proceed) proceed.disabled = true;
  }

  function submitBackupAccept(prompt, confirmRisk) {
    var form = root.querySelector("[data-backup-uplink-accept-form]");
    if (!form || !prompt || !prompt.port) return;
    var portInput = root.querySelector("[data-backup-uplink-accept-port]");
    var confirmInput = root.querySelector("[data-backup-uplink-accept-confirm]");
    if (portInput) portInput.value = prompt.port;
    if (confirmInput) confirmInput.value = confirmRisk ? "1" : "";
    form.submit();
  }

  function submitUplinkAccept(prompt, confirmRisk) {
    var form = root.querySelector("[data-uplink-accept-form]");
    if (!form || !prompt || !prompt.port) return;
    var portInput = root.querySelector("[data-uplink-accept-port]");
    var confirmInput = root.querySelector("[data-uplink-accept-confirm]");
    if (portInput) portInput.value = prompt.port;
    if (confirmInput) confirmInput.value = confirmRisk ? "1" : "";
    form.submit();
  }

  function openUplinkRiskDialog(options) {
    var opts = options || {};
    var prompt = opts.prompt || null;
    var form = opts.form || null;
    var risk = opts.risk || (prompt && prompt.risk) || {};
    var message = opts.message || (prompt && prompt.message) || risk.summary || "";
    var preserveCheckbox = !!opts.preserveCheckbox;
    if (!preserveCheckbox) {
      pendingUplinkPrompt = prompt;
      pendingUplinkForm = form;
      pendingBackupPrompt = opts.backupPrompt || null;
      pendingFormRisk = risk;
    } else if (risk) {
      pendingFormRisk = risk;
    }

    var titleEl = root.querySelector("[data-uplink-risk-title]");
    if (titleEl && opts.title) {
      titleEl.textContent = opts.title;
    } else if (titleEl && !preserveCheckbox) {
      titleEl.textContent = opts.title || "Before switching Internet port";
    }

    var summary = root.querySelector("[data-uplink-risk-summary]");
    if (summary) summary.textContent = message;

    var list = root.querySelector("[data-uplink-risk-list]");
    var risks = risk.risks || [];
    if (list) {
      if (risks.length) {
        list.innerHTML = risks.map(function (line) {
          return "<li>" + esc(line) + "</li>";
        }).join("");
        setHidden(list, false);
      } else {
        list.innerHTML = "";
        setHidden(list, true);
      }
    }
    var blockingEl = root.querySelector("[data-uplink-risk-blocking]");
    var confirmWrap = root.querySelector("[data-uplink-risk-confirm-wrap]");
    var tunnelGate = root.querySelector("[data-uplink-risk-tunnel-gate]");
    var tunnelLink = root.querySelector("[data-uplink-risk-tunnel-link]");
    var checkbox = root.querySelector("[data-uplink-risk-checkbox]");
    var blocking = !!risk.blocking;
    var needsTunnel = !!risk.needs_tunnel;
    var needConfirm = riskNeedsConfirm(risk);
    if (!preserveCheckbox && checkbox) checkbox.checked = false;
    if (blockingEl) {
      if (blocking) {
        blockingEl.textContent =
          risk.summary ||
          "This change cannot be applied until the disabled port is enabled.";
        setHidden(blockingEl, false);
      } else {
        setHidden(blockingEl, true);
      }
    }
    if (tunnelGate) {
      setHidden(tunnelGate, !needsTunnel);
    }
    if (tunnelLink) {
      tunnelLink.href =
        risk.tunnel_setup_url || routerDetailUrl || tunnelLink.getAttribute("href") || "#";
    }
    if (confirmWrap) {
      setHidden(confirmWrap, blocking || !needConfirm);
    }
    syncRiskProceedButton(risk, form || pendingUplinkForm);
    if (!preserveCheckbox) {
      setWanRecoveryScript(
        opts.recoveryScript || rollbackScriptFromRisk(risk) || ""
      );
    }
    riskDialogOpen = true;
    setHidden(root.querySelector("[data-uplink-risk-backdrop]"), false);
    setHidden(root.querySelector("[data-uplink-risk-dialog]"), false);
  }

  function refreshOpenRiskDialog() {
    if (!riskDialogOpen || !lastPortsData) return;
    var form = pendingUplinkForm;
    var risk = pendingFormRisk;
    if (form) {
      var applyMode = form.getAttribute("data-uplink-risk-apply");
      var fresh =
        applyMode &&
        lastPortsData.uplink_apply_risks &&
        lastPortsData.uplink_apply_risks[applyMode];
      if (fresh) risk = fresh;
    } else if (pendingUplinkPrompt && pendingUplinkPrompt.port) {
      var portRisk =
        lastPortsData.wan_switch_risks &&
        lastPortsData.wan_switch_risks[pendingUplinkPrompt.port];
      if (portRisk) {
        risk = portRisk;
        pendingUplinkPrompt.risk = portRisk;
      }
    }
    if (!risk) return;
    openUplinkRiskDialog({
      form: form,
      prompt: pendingUplinkPrompt,
      backupPrompt: pendingBackupPrompt,
      risk: risk,
      message: risk.summary,
      preserveCheckbox: true,
    });
  }

  function renderBackupUplinkPrompt(prompt) {
    var banner = root.querySelector("[data-backup-uplink-prompt]");
    if (!banner) return;
    if (!prompt || !prompt.port || isBackupDismissed(prompt.port)) {
      setHidden(banner, true);
      return;
    }
    var body = root.querySelector("[data-backup-uplink-prompt-body]");
    if (body) body.textContent = " " + (prompt.message || "");
    if (prompt.risk && (prompt.risk.blocking || prompt.risk.needs_tunnel)) {
      banner.classList.remove("is-info");
      banner.classList.add("is-warn");
    } else {
      banner.classList.remove("is-warn");
      banner.classList.add("is-info");
    }
    setHidden(banner, false);
  }

  function renderUplinkPrompt(prompt) {
    var banner = root.querySelector("[data-uplink-prompt]");
    if (!banner) return;
    if (!prompt || !prompt.port || isUplinkDismissed(prompt.port)) {
      setHidden(banner, true);
      return;
    }
    var body = root.querySelector("[data-uplink-prompt-body]");
    if (body) {
      body.textContent = " " + (prompt.message || "");
    }
    if (prompt.risk && (prompt.risk.blocking || prompt.risk.needs_tunnel)) {
      banner.classList.remove("is-info");
      banner.classList.add("is-warn");
    } else {
      banner.classList.remove("is-warn");
      banner.classList.add("is-info");
    }
    setHidden(banner, false);
  }

  function isApiConnectivityError(message) {
    var msg = String(message || "").toLowerCase();
    return (
      msg.indexOf("8728") >= 0 ||
      msg.indexOf("timed out") >= 0 ||
      msg.indexOf("could not reach") >= 0 ||
      msg.indexOf("could not read ports") >= 0 ||
      msg.indexOf("could not load ports") >= 0
    );
  }

  function apiRecoveryScript(data) {
    return ((data && data.terminal_script) || "").trim() || defaultApiScript;
  }

  function openApiRecoveryModal(script, message) {
    var text = (script || "").trim() || defaultApiScript;
    if (!text) return;
    var pre = root.querySelector("[data-api-recovery-modal-script]");
    var inlinePre = root.querySelector("[data-ports-api-script]");
    if (pre) pre.textContent = text;
    if (inlinePre) inlinePre.textContent = text;
    var lead = root.querySelector("[data-api-recovery-lead]");
    if (lead) {
      lead.innerHTML =
        (message ? esc(message) + " " : "") +
        "Open Winbox on a LAN port, paste the commands below in " +
        "<strong>New Terminal</strong>, press Enter, then click Retry.";
    }
    setHidden(root.querySelector("[data-api-recovery-backdrop]"), false);
    setHidden(root.querySelector("[data-api-recovery-dialog]"), false);
  }

  function closeApiRecoveryModal() {
    setHidden(root.querySelector("[data-api-recovery-backdrop]"), true);
    setHidden(root.querySelector("[data-api-recovery-dialog]"), true);
  }

  function setPortsApiRecovery(script) {
    var wrap = root.querySelector("[data-ports-api-recovery]");
    var pre = root.querySelector("[data-ports-api-script]");
    if (pre) pre.textContent = script || "";
    if (wrap) setHidden(wrap, !script);
  }

  function apply(data) {
    setHidden(root.querySelector("[data-ports-loading-ui]"), true);

    if (!data || !data.ok) {
      var err = root.querySelector("[data-ports-error]");
      var errText = root.querySelector("[data-ports-error-text]");
      var errorMsg = (data && data.error) || "Could not read ports.";
      if (errText) errText.textContent = errorMsg;
      var script = isApiConnectivityError(errorMsg) ? apiRecoveryScript(data) : "";
      setPortsApiRecovery(script);
      var wasOk = lastConnectOk === true;
      var isFirstFail = lastConnectOk === null;
      if (script && (wasOk || isFirstFail)) {
        openApiRecoveryModal(script, errorMsg);
      }
      lastConnectOk = false;
      setHidden(err, false);
      maybeShowWanRecoveryModal(data);
      setHidden(root.querySelector("[data-ports-grid]"), true);
      setHidden(root.querySelector("[data-ports-empty]"), true);
      setHidden(root.querySelector("[data-ports-summary]"), true);
      setHidden(root.querySelector("[data-ports-hint]"), true);
      setHidden(root.querySelector("[data-ports-map]"), true);
      setHidden(root.querySelector("[data-uplink-config]"), true);
      setHidden(root.querySelector("[data-ports-assign]"), true);
      setHidden(root.querySelector("[data-ports-auto-form]"), true);
      return;
    }

    lastPortsData = data;

    if (data.ok) {
      clearWanSwitchAttempt();
      lastConnectOk = true;
      closeApiRecoveryModal();
    }
    refreshOpenRiskDialog();

    setHidden(root.querySelector("[data-ports-error]"), true);
    setPortsApiRecovery("");
    setHidden(root.querySelector("[data-ports-auto-form]"), suspended);

    var info = root.querySelector("[data-ports-info]");
    if (info) {
      if (data.auto_assigned && data.auto_assigned_message) {
        info.textContent = data.auto_assigned_message;
        setHidden(info, false);
      } else if (data.smart_balance_auto && data.smart_balance_auto.ok && data.smart_balance_auto.message) {
        info.textContent = data.smart_balance_auto.message;
        setHidden(info, false);
      } else if (data.role_sync_message) {
        info.textContent = data.role_sync_message;
        setHidden(info, false);
      } else {
        setHidden(info, true);
      }
    }

    var primary = data.primary_wan_ports || [];
    var bond = data.bond_member_ports || [];
    var lan = data.lan_ports || [];
    var unused = data.unused_ports || [];
    var mode = data.uplink_mode || "single";

    var sumInternet = root.querySelector("[data-sum-internet]");
    var sumInternetMeta = root.querySelector("[data-sum-internet-meta]");
    if (sumInternet) {
      if (primary.length) sumInternet.textContent = primary.join(", ");
      else if (bond.length) sumInternet.textContent = "Bond " + bond.join(" + ");
      else sumInternet.textContent = "Not set";
    }
    if (sumInternetMeta) {
      if (mode === "bond") {
        sumInternetMeta.textContent = "Bonded uplink";
      } else if (mode === "failover") {
        sumInternetMeta.textContent = "Failover uplink";
      } else if (mode === "balance" || mode === "smart_balance") {
        var wmapMeta = data.uplink_weights || {};
        var members = (data.primary_wan_ports || []).concat(data.backup_wan_ports || []);
        var wvals = members.map(function (p) {
          return parseInt(wmapMeta[p], 10) || 0;
        }).filter(function (v) { return v > 0; });
        if (wvals.length >= 2) {
          var wtotal = wvals.reduce(function (a, b) { return a + b; }, 0);
          var pcts = wvals.map(function (v) { return Math.round((100 * v) / wtotal); });
          sumInternetMeta.textContent = "Weighted ~" + pcts.join("/") + "%";
        } else {
          sumInternetMeta.textContent = "Load-balanced (weighted)";
        }
      } else {
        sumInternetMeta.textContent = "Main WAN";
      }
    }
    var sumLan = root.querySelector("[data-sum-lan]");
    var sumLanMeta = root.querySelector("[data-sum-lan-meta]");
    if (sumLan) sumLan.textContent = lan.length ? lan.length + " port" + (lan.length !== 1 ? "s" : "") : "None";
    if (sumLanMeta) sumLanMeta.textContent = lan.length ? lan.join(", ") : "Assign customer LAN ports";
    var sumUnused = root.querySelector("[data-sum-unused]");
    var sumUnusedMeta = root.querySelector("[data-sum-unused-meta]");
    if (sumUnused) sumUnused.textContent = String(unused.length || 0);
    if (sumUnusedMeta) sumUnusedMeta.textContent = unused.length ? unused.join(", ") : "No unused ports";

    var physical = data.physical_ports || [];
    setHidden(root.querySelector("[data-ports-summary]"), !physical.length);
    setHidden(root.querySelector("[data-ports-hint]"), !physical.length);
    var sugWrap = root.querySelector("[data-suggested-wan-wrap]");
    var sug = root.querySelector("[data-suggested-wan]");
    if (data.suggested_wan) {
      if (sug) sug.textContent = data.suggested_wan;
      setHidden(sugWrap, false);
    } else {
      setHidden(sugWrap, true);
    }

    var modeLabel = root.querySelector("[data-uplink-mode-label]");
    if (modeLabel) modeLabel.textContent = data.uplink_mode_label || "Single WAN";
    var modeMeta = root.querySelector("[data-uplink-mode-meta]");
    if (modeMeta) {
      var ports = data.uplink_ports || [];
      if (mode === "bond" && ports.length) {
        modeMeta.textContent =
          (data.bond_interface || "") + " · " + (data.bond_mode || "") + " · " + ports.join(", ");
      } else if ((mode === "balance" || mode === "smart_balance") && ports.length) {
        var wmap = data.uplink_weights || {};
        var wbits = ports
          .map(function (p) {
            return wmap[p] ? p + " " + wmap[p] + " Mbps" : p;
          })
          .join(" + ");
        modeMeta.textContent =
          (mode === "smart_balance" ? "Smart sharing " : "Sharing ") + wbits;
      } else if (mode === "failover" && ports.length) {
        modeMeta.textContent =
          "Primary " +
          ports[0] +
          (data.failover_backup_label ? " · Backup " + data.failover_backup_label : "");
      } else if (data.wan_interface) {
        modeMeta.textContent = "WAN " + data.wan_interface;
      } else {
        modeMeta.textContent = "";
      }
    }
    setHidden(root.querySelector("[data-clear-uplink-form]"), mode === "single" || suspended);

    var healthEl = root.querySelector("[data-uplink-health]");
    if (healthEl) {
      var live = data.uplink_live || {};
      if (mode === "balance" || mode === "smart_balance") {
        var shareLine = ((data.wan_share && data.wan_share.shares) || [])
          .map(function (s) {
            return (s.name || "?") + " " + (s.pct != null ? s.pct + "%" : "—");
          })
          .join(" · ");
        var memberCount = (data.primary_wan_ports || []).length + (data.backup_wan_ports || []).length;
        var slowPorts = ((data.smart_balance_status && data.smart_balance_status.slow_ports) || []);
        if (!data.balance_router_applied) {
          healthEl.textContent = data.balance_apply_hint || (
            mode === "smart_balance"
              ? "Click Apply smart balance to push PCC + monitor to the MikroTik."
              : "Click Apply load balance to push PCC rules to the MikroTik."
          );
          healthEl.className = "mk-uplink-health is-warn";
        } else if (slowPorts.length && mode === "smart_balance") {
          healthEl.textContent = "Slow ISP sidelined from new connections: " + slowPorts.join(", ");
          healthEl.className = "mk-uplink-health is-warn";
        } else if (shareLine) {
          healthEl.textContent = "Live share · " + shareLine;
          healthEl.className = "mk-uplink-health is-ok";
        } else {
          healthEl.textContent =
            (mode === "smart_balance" ? "Smart PCC across " : "PCC load balance across ") +
            (data.uplink_ports || []).join(" + ") +
            (memberCount >= 2 ? " (" + memberCount + " ISPs)" : "");
          healthEl.className = "mk-uplink-health is-ok";
        }
        setHidden(healthEl, false);
      } else if (mode === "single" || !live.ok) {
        setHidden(healthEl, true);
        healthEl.textContent = "";
        healthEl.className = "mk-uplink-health";
      } else if (mode === "bond") {
        var bondLive = (live.bonds || [])[0];
        if (bondLive && bondLive.running) {
          healthEl.textContent = "Bond up · " + (bondLive.slaves || []).join(", ");
          healthEl.className = "mk-uplink-health is-ok";
        } else {
          healthEl.textContent = "Bond not running on router yet";
          healthEl.className = "mk-uplink-health is-warn";
        }
        setHidden(healthEl, false);
      } else if (mode === "failover") {
        var checked = live.checked_routes || [];
        var clients = live.failover_clients || [];
        if (checked.length) {
          var active = checked.filter(function (r) { return r.active; })[0];
          healthEl.textContent = active
            ? "Active via " + (active.gateway || "gateway") + " (ping-checked)"
            : "Failover routes installed · waiting for gateway";
          healthEl.className = "mk-uplink-health " + (active ? "is-ok" : "is-warn");
        } else if (clients.length >= 2) {
          healthEl.textContent =
            "Distance failover on " +
            clients
              .map(function (c) {
                return (c.interface || "?") + "@" + (c.distance || "?");
              })
              .join(", ");
          healthEl.className = "mk-uplink-health is-ok";
        } else {
          healthEl.textContent = "Apply failover to push routes to the MikroTik";
          healthEl.className = "mk-uplink-health is-warn";
        }
        setHidden(healthEl, false);
      } else {
        setHidden(healthEl, true);
      }
    }

    renderFlow(data);
    renderFace(data);

    // Always follow server uplink mode (no sessionStorage goal drift).
    setSelectedGoal(data.uplink_mode || "single", { skipRerender: true });

    updatePortsAssignSection(data);
    renderPortCards(data);

    var healthBanner = root.querySelector("[data-ports-health]");
    if (healthBanner) {
      var alerts = data.uplink_health_alerts || [];
      if (alerts.length) {
        healthBanner.innerHTML = alerts.map(function (a) {
          return "<p>" + esc((a && a.message) || "") + "</p>";
        }).join("");
        healthBanner.className =
          "mk-banner mk-ports-health " +
          (alerts.some(function (a) { return a && a.level === "warn"; }) ? "is-warn" : "is-info");
        setHidden(healthBanner, false);
      } else {
        healthBanner.innerHTML = "";
        setHidden(healthBanner, true);
      }
    }

    var uplinkConfig = root.querySelector("[data-uplink-config]");
    if (!suspended && physical.length) {
      setHidden(uplinkConfig, false);
      chipList(root.querySelector("[data-bond-list]"), bond, "is-bond", data.ports);
      setHidden(root.querySelector("[data-bond-empty]"), !!bond.length);
      setHidden(root.querySelector("[data-bond-list]"), !bond.length);
      var canBond = !!data.can_apply_bond;
      var bondBtn = root.querySelector("[data-apply-bond]");
      if (bondBtn) bondBtn.disabled = !canBond;
      var bondReadiness = root.querySelector("[data-bond-readiness]");
      if (bondReadiness) {
        var bondHintText = data.bond_apply_hint || "";
        bondReadiness.textContent = bondHintText;
        bondReadiness.className =
          "mk-help-note" + (canBond ? " is-ok" : bondHintText ? " is-warn" : "");
        setHidden(bondReadiness, !bondHintText);
      }
      setHidden(root.querySelector("[data-bond-hint]"), canBond || !!(data.bond_apply_hint));
      var autoBondForm = root.querySelector("[data-bond-auto-form]");
      if (autoBondForm) {
        setHidden(autoBondForm, !data.can_auto_setup_bond);
      }

      chipList(root.querySelector("[data-primary-list]"), primary.length === 1 ? primary : [], "is-primary", data.ports);
      setHidden(root.querySelector("[data-primary-list]"), primary.length !== 1);
      setHidden(root.querySelector("[data-primary-empty]"), primary.length !== 0);
      setHidden(root.querySelector("[data-primary-warn]"), primary.length <= 1);
      var backups = data.backup_wan_ports || [];
      chipList(root.querySelector("[data-backup-list]"), backups, "is-backup", data.ports);
      setHidden(root.querySelector("[data-backup-list]"), !backups.length);
      setHidden(root.querySelector("[data-backup-empty]"), !!backups.length);
      var canFail = !!data.can_apply_failover;
      var failBtn = root.querySelector("[data-apply-failover]");
      if (failBtn) failBtn.disabled = !canFail;
      setHidden(root.querySelector("[data-failover-hint]"), canFail);

      var balanceMembers = primary.concat(data.backup_wan_ports || []);
      chipList(root.querySelector("[data-balance-list]"), balanceMembers, "is-balance", data.ports);
      setHidden(root.querySelector("[data-balance-list]"), balanceMembers.length < 2);
      setHidden(root.querySelector("[data-balance-empty]"), balanceMembers.length >= 2);
      renderBalanceWeights(balanceMembers, data.uplink_weights || {});
      var canBalance = !!data.can_apply_balance;
      var balanceBtn = root.querySelector("[data-apply-balance]");
      if (balanceBtn) balanceBtn.disabled = !canBalance;
      var balanceHint = root.querySelector("[data-balance-hint]");
      if (balanceHint) {
        balanceHint.textContent = data.balance_apply_hint || "Need 1 Internet + at least 1 Shared ISP, all link up.";
        setHidden(balanceHint, false);
      }

      var smartMembers = primary.concat(data.backup_wan_ports || []);
      chipList(root.querySelector("[data-smart-balance-list]"), smartMembers, "is-balance", data.ports);
      setHidden(root.querySelector("[data-smart-balance-list]"), smartMembers.length < 2);
      setHidden(root.querySelector("[data-smart-balance-empty]"), smartMembers.length >= 2);
      renderBalanceWeights(smartMembers, data.uplink_weights || {}, "smart-balance");
      var canSmart = !!data.can_apply_smart_balance;
      var smartBtn = root.querySelector("[data-apply-smart-balance]");
      if (smartBtn) smartBtn.disabled = !canSmart;
      var smartHint = root.querySelector("[data-smart-balance-hint]");
      if (smartHint) {
        smartHint.textContent = data.balance_apply_hint || "Need 1 Internet + at least 1 Shared ISP, all link up.";
        setHidden(smartHint, false);
      }
      var autoSmartForm = root.querySelector("[data-smart-balance-auto-form]");
      if (autoSmartForm) {
        var showAuto =
          (data.uplink_mode || "") === "smart_balance" &&
          !!data.can_auto_setup_smart_balance &&
          !data.smart_balance_applied;
        setHidden(autoSmartForm, !showAuto);
      }
    } else {
      setHidden(uplinkConfig, true);
      setHidden(root.querySelector("[data-ports-assign]"), true);
    }

    renderUplinkPrompt(data.uplink_prompt);
    renderBackupUplinkPrompt(data.backup_uplink_prompt);
  }

  function refresh(options) {
    var opts = options || {};
    var silent = !!opts.silent;
    if (!silent) {
      setHidden(root.querySelector("[data-ports-loading-ui]"), false);
      setHidden(root.querySelector("[data-ports-error]"), true);
    }
    return fetch(liveUrl + "?refresh=1", {
      headers: { Accept: "application/json", "X-Requested-With": "XMLHttpRequest" },
      credentials: "same-origin"
    })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        apply(data);
        return data;
      })
      .catch(function () {
        apply({
          ok: false,
          error: "Could not load ports from the MikroTik.",
          terminal_script: defaultApiScript,
        });
        maybeShowWanRecoveryModal();
      });
  }

  var livePollTimer = null;
  function startLivePolling() {
    if (livePollTimer || suspended) return;
    livePollTimer = window.setInterval(function () {
      if (document.hidden) return;
      refresh({ silent: true });
    }, 3000);
  }
  function stopLivePolling() {
    if (!livePollTimer) return;
    window.clearInterval(livePollTimer);
    livePollTimer = null;
  }

  document.addEventListener("visibilitychange", function () {
    if (document.hidden) return;
    refresh({ silent: true });
  });
  window.addEventListener("beforeunload", stopLivePolling);

  root.addEventListener("change", function (event) {
    var select = event.target.closest("[data-uplink-goal-select]");
    if (!select || !root.contains(select)) return;
    var goal = select.value || "single";
    setSelectedGoal(goal, { skipRerender: true });
    var goalForm = root.querySelector("[data-uplink-goal-form]");
    var goalInput = root.querySelector("[data-uplink-goal-input]");
    if (goalForm && goalInput) {
      goalInput.value = goal;
      goalForm.submit();
      return;
    }
    var panel = root.querySelector('[data-goal-panel="' + (selectedGoal || "single") + '"]');
    if (panel) panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  });

  root.addEventListener("click", function (event) {
    var dismissBtn = event.target.closest("[data-uplink-prompt-dismiss]");
    if (dismissBtn && root.contains(dismissBtn)) {
      event.preventDefault();
      var port = (lastPortsData && lastPortsData.uplink_prompt && lastPortsData.uplink_prompt.port) || "";
      dismissUplinkPrompt(port);
      return;
    }
    var backupDismiss = event.target.closest("[data-backup-uplink-prompt-dismiss]");
    if (backupDismiss && root.contains(backupDismiss)) {
      event.preventDefault();
      var bport = (lastPortsData && lastPortsData.backup_uplink_prompt && lastPortsData.backup_uplink_prompt.port) || "";
      dismissBackupPrompt(bport);
      return;
    }
    var backupAccept = event.target.closest("[data-backup-uplink-prompt-accept]");
    if (backupAccept && root.contains(backupAccept)) {
      event.preventDefault();
      var bprompt = lastPortsData && lastPortsData.backup_uplink_prompt;
      if (!bprompt) return;
      var brisk = bprompt.risk || {};
      if (brisk.blocking) {
        openUplinkRiskDialog({
          backupPrompt: bprompt,
          prompt: bprompt,
          title: "Before marking backup internet",
        });
        return;
      }
      if (brisk.safe) {
        submitBackupAccept(bprompt, false);
        return;
      }
      openUplinkRiskDialog({
        backupPrompt: bprompt,
        prompt: bprompt,
        title: "Before marking backup internet",
      });
      return;
    }
    var switchBtn = event.target.closest("[data-uplink-prompt-switch]");
    if (switchBtn && root.contains(switchBtn)) {
      event.preventDefault();
      var prompt = lastPortsData && lastPortsData.uplink_prompt;
      if (!prompt) return;
      var risk = prompt.risk || {};
      if (risk.blocking) {
        openUplinkRiskDialog({
          prompt: prompt,
          title: "Before switching Internet port",
          recoveryScript: prompt.recovery_script || "",
        });
        return;
      }
      if (risk.safe) {
        submitUplinkAccept(prompt, false);
        return;
      }
      openUplinkRiskDialog({
        prompt: prompt,
        title: "Before switching Internet port",
        recoveryScript: prompt.recovery_script || "",
      });
      return;
    }
    var recoveryCopy = event.target.closest("[data-wan-recovery-copy]");
    if (recoveryCopy && root.contains(recoveryCopy)) {
      event.preventDefault();
      var inlineScript = root.querySelector("[data-wan-recovery-script]");
      copyTextToClipboard(inlineScript ? inlineScript.textContent : "", recoveryCopy);
      return;
    }
    var apiCopy = event.target.closest("[data-ports-api-copy]");
    if (apiCopy && root.contains(apiCopy)) {
      event.preventDefault();
      var apiScript = root.querySelector("[data-ports-api-script]");
      copyTextToClipboard(apiScript ? apiScript.textContent : "", apiCopy);
      return;
    }
    var apiModalCopy = event.target.closest("[data-api-recovery-modal-copy]");
    if (apiModalCopy && root.contains(apiModalCopy)) {
      event.preventDefault();
      var apiModalScript = root.querySelector("[data-api-recovery-modal-script]");
      copyTextToClipboard(apiModalScript ? apiModalScript.textContent : "", apiModalCopy);
      return;
    }
    var apiDismiss = event.target.closest("[data-api-recovery-dismiss]");
    if (apiDismiss && root.contains(apiDismiss)) {
      event.preventDefault();
      closeApiRecoveryModal();
      return;
    }
    var apiBackdrop = event.target.closest("[data-api-recovery-backdrop]");
    if (apiBackdrop && root.contains(apiBackdrop)) {
      event.preventDefault();
      closeApiRecoveryModal();
      return;
    }
    var recoveryModalCopy = event.target.closest("[data-wan-recovery-modal-copy]");
    if (recoveryModalCopy && root.contains(recoveryModalCopy)) {
      event.preventDefault();
      var modalScript = root.querySelector("[data-wan-recovery-modal-script]");
      copyTextToClipboard(modalScript ? modalScript.textContent : "", recoveryModalCopy);
      return;
    }
    var recoveryDismiss = event.target.closest("[data-wan-recovery-dismiss]");
    if (recoveryDismiss && root.contains(recoveryDismiss)) {
      event.preventDefault();
      closeWanRecoveryModal();
      return;
    }
    var recoveryBackdrop = event.target.closest("[data-wan-recovery-backdrop]");
    if (recoveryBackdrop && root.contains(recoveryBackdrop)) {
      event.preventDefault();
      closeWanRecoveryModal();
      return;
    }
    var riskCancel = event.target.closest("[data-uplink-risk-cancel]");
    if (riskCancel && root.contains(riskCancel)) {
      event.preventDefault();
      closeUplinkRiskDialog();
      return;
    }
    var riskProceed = event.target.closest("[data-uplink-risk-proceed]");
    if (riskProceed && root.contains(riskProceed)) {
      event.preventDefault();
      var needConfirm = false;
      if (pendingUplinkForm) {
        var applyMode = pendingUplinkForm.getAttribute("data-uplink-risk-apply");
        var formRisk =
          pendingFormRisk ||
          (lastPortsData &&
            lastPortsData.uplink_apply_risks &&
            applyMode &&
            lastPortsData.uplink_apply_risks[applyMode]);
        if (formRisk && formRisk.blocking) return;
        needConfirm = riskNeedsConfirm(formRisk);
        var checkbox = root.querySelector("[data-uplink-risk-checkbox]");
        if (needConfirm && checkbox && !checkbox.checked) return;
        var confirmField = pendingUplinkForm.querySelector("[name='confirm_risk']");
        if (confirmField) confirmField.value = needConfirm ? "1" : "";
        if (pendingUplinkForm.classList.contains("mk-role-form")) {
          var switchPort = (pendingUplinkForm.querySelector('[name="port_name"]') || {}).value || "";
          var switchPrimary = ((lastPortsData && lastPortsData.primary_wan_ports) || [])[0] || "";
          rememberWanSwitchAttempt(
            switchPort,
            (formRisk && rollbackScriptFromRisk(formRisk)) || readStoredWanRecoveryScript(),
            switchPrimary
          );
        } else if (formRisk && rollbackScriptFromRisk(formRisk)) {
          rememberWanSwitchAttempt("", rollbackScriptFromRisk(formRisk), "");
        }
        pendingUplinkForm.submit();
        closeUplinkRiskDialog();
        return;
      }
      if (pendingBackupPrompt) {
        var brisk = pendingBackupPrompt.risk || {};
        if (brisk.blocking) return;
        needConfirm = riskNeedsConfirm(brisk);
        var cb = root.querySelector("[data-uplink-risk-checkbox]");
        if (needConfirm && cb && !cb.checked) return;
        submitBackupAccept(pendingBackupPrompt, needConfirm);
        closeUplinkRiskDialog();
        return;
      }
      if (!pendingUplinkPrompt || (pendingUplinkPrompt.risk && pendingUplinkPrompt.risk.blocking)) return;
      needConfirm = riskNeedsConfirm(pendingUplinkPrompt.risk);
      var riskCheckbox = root.querySelector("[data-uplink-risk-checkbox]");
      if (needConfirm && riskCheckbox && !riskCheckbox.checked) return;
      rememberWanSwitchAttempt(
        pendingUplinkPrompt.port,
        pendingUplinkPrompt.rollback_recovery_script ||
          pendingUplinkPrompt.recovery_script ||
          readStoredWanRecoveryScript(),
        pendingUplinkPrompt.current_port || ""
      );
      submitUplinkAccept(pendingUplinkPrompt, needConfirm);
      closeUplinkRiskDialog();
      return;
    }
    var preset = event.target.closest("[data-balance-preset], [data-smart-balance-preset]");
    if (preset && root.contains(preset)) {
      event.preventDefault();
      if (preset.hasAttribute("data-smart-balance-preset")) {
        applyBalancePreset(preset.getAttribute("data-smart-balance-preset") || "equal", "smart-balance");
      } else {
        applyBalancePreset(preset.getAttribute("data-balance-preset") || "equal", "balance");
      }
      return;
    }
    var jump = event.target.closest("[data-jump-port]");
    if (!jump || !root.contains(jump)) return;
    event.preventDefault();
    jumpToPortCard(jump.getAttribute("data-jump-port") || "");
  });

  root.addEventListener("submit", function (event) {
    var form = event.target;
    if (!form || !root.contains(form)) return;

    if (form.hasAttribute("data-bond-auto-form")) {
      var bondPanel = root.querySelector('form.mk-goal-panel[data-goal-panel="bond"]');
      if (bondPanel) {
        var modeSelect = bondPanel.querySelector('select[name="bond_mode"]');
        var nameInput = bondPanel.querySelector('input[name="bond_name"]');
        var modeHidden = form.querySelector('input[name="bond_mode"]');
        var nameHidden = form.querySelector('input[name="bond_name"]');
        if (modeSelect && modeHidden) modeHidden.value = modeSelect.value;
        if (nameInput && nameHidden) nameHidden.value = nameInput.value;
      }
    }

    if (form.classList && form.classList.contains("mk-role-form")) {
      var roleInput = form.querySelector('input[name="role"]');
      if (!roleInput || roleInput.value !== "wan") return;
      if (!lastPortsData || (lastPortsData.uplink_mode || "single") !== "single") return;
      var portInput = form.querySelector('input[name="port_name"]');
      var portName = portInput ? (portInput.value || "").trim() : "";
      var primary = ((lastPortsData.primary_wan_ports || [])[0] || "").trim();
      if (!portName || portName === primary) return;
      var risk = (lastPortsData.wan_switch_risks || {})[portName];
      storePendingWanSwitch(
        portName,
        primary,
        rollbackScriptFromRisk(risk)
      );
      if (!risk || risk.safe) return;
      event.preventDefault();
      var fromLabel = primary || "current port";
      openUplinkRiskDialog({
        form: form,
        risk: risk,
        message: "Move Internet from " + fromLabel + " to " + portName + "?",
        title: "Before switching Internet port",
        recoveryScript: rollbackScriptFromRisk(risk),
      });
      return;
    }

    var mode = form.getAttribute("data-uplink-risk-apply");
    if (!mode) return;
    var risks = lastPortsData && lastPortsData.uplink_apply_risks;
    var risk = risks && risks[mode];
    if (!risk) return;
    if (risk.safe && !risk.blocking) return;
    event.preventDefault();
    var titles = {
      bond: "Before applying bonding",
      failover: "Before applying failover",
      balance: "Before applying load balance",
      smart_balance: "Before applying smart balance",
      clear: "Before resetting to single WAN",
    };
    openUplinkRiskDialog({
      form: form,
      risk: risk,
      message: risk.summary,
      title: titles[mode] || "Before applying uplink change",
      recoveryScript: risk.recovery_script || "",
    });
  });

  var riskCheckbox = root.querySelector("[data-uplink-risk-checkbox]");
  if (riskCheckbox) {
    riskCheckbox.addEventListener("change", function () {
      if (pendingUplinkForm) {
        var applyMode = pendingUplinkForm.getAttribute("data-uplink-risk-apply");
        var formRisk =
          pendingFormRisk ||
          (lastPortsData &&
            lastPortsData.uplink_apply_risks &&
            applyMode &&
            lastPortsData.uplink_apply_risks[applyMode]);
        if (formRisk) syncRiskProceedButton(formRisk, pendingUplinkForm);
        return;
      }
      if (pendingBackupPrompt && pendingBackupPrompt.risk) {
        syncRiskProceedButton(pendingBackupPrompt.risk, null);
        return;
      }
      if (pendingUplinkPrompt && pendingUplinkPrompt.risk) {
        syncRiskProceedButton(pendingUplinkPrompt.risk, null);
      }
    });
  }

  var retry = root.querySelector("[data-ports-retry]");
  if (retry) retry.addEventListener("click", function () { refresh(); });
  refresh().then(function () { startLivePolling(); });
})();
