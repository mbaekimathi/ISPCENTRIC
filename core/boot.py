"""Background work that starts whenever the Django process starts.

Local ``runserver`` and hosted gunicorn/Passenger both load AppConfig.ready,
so WireGuard peers and subscription access refresh without extra commands.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time

logger = logging.getLogger(__name__)

_started = False

_SKIP_COMMANDS = (
    "migrate",
    "makemigrations",
    "check",
    "test",
    "shell",
    "dbshell",
    "collectstatic",
    "wireguard_peer",
)


def should_start_runtime_tasks() -> bool:
    """False during one-shot management commands and the runserver reloader parent."""
    if any(cmd in sys.argv for cmd in _SKIP_COMMANDS):
        return False
    if "--no-sweep" in sys.argv and "--no-tunnel-sync" in sys.argv:
        return False
    if "runserver" in sys.argv or "devserver" in sys.argv:
        return os.environ.get("RUN_MAIN") == "true"
    return True


def _subscription_sweep_enabled() -> bool:
    if "--no-sweep" in sys.argv:
        return False
    return os.getenv("SUBSCRIPTION_SWEEP_ENABLED", "true").strip().lower() not in {
        "0",
        "false",
        "no",
    }


def _tunnel_sync_enabled() -> bool:
    if "--no-tunnel-sync" in sys.argv:
        return False
    return os.getenv("WIREGUARD_AUTO_SYNC", "true").strip().lower() not in {
        "0",
        "false",
        "no",
    }


def _subscription_sweep_interval_sec() -> float:
    # Match deploy/systemd/ispcentric-sweep.timer (2 min) so local runserver
    # does not leave expired clients surfing for ~5 minutes.
    try:
        return max(60.0, float(os.getenv("SUBSCRIPTION_SWEEP_INTERVAL_SEC", "120")))
    except (TypeError, ValueError):
        return 120.0


def _subscription_sweep_startup_delay_sec() -> float:
    """Delay the first sweep so a just-started process can serve STK/recharge."""
    try:
        return max(0.0, float(os.getenv("SUBSCRIPTION_SWEEP_STARTUP_DELAY_SEC", "20")))
    except (TypeError, ValueError):
        return 20.0


def _usage_sample_enabled() -> bool:
    # Independent of subscription --no-sweep: usage history must keep building
    # even when operators pause access sweeps.
    if "--no-usage-sample" in sys.argv:
        return False
    return os.getenv("USAGE_SAMPLE_ENABLED", "true").strip().lower() not in {
        "0",
        "false",
        "no",
    }


def _usage_sample_interval_sec() -> float:
    """How often to snapshot PPPoE/Hotspot usage from every org's MikroTiks."""
    try:
        # Default 60s — dense enough for trend charts, light on RouterOS.
        return max(30.0, float(os.getenv("USAGE_SAMPLE_INTERVAL_SEC", "60")))
    except (TypeError, ValueError):
        return 60.0


def _usage_sample_startup_delay_sec() -> float:
    try:
        return max(0.0, float(os.getenv("USAGE_SAMPLE_STARTUP_DELAY_SEC", "35")))
    except (TypeError, ValueError):
        return 35.0


_USAGE_SAMPLE_LOCK_KEY = "usage_sample_bg_lock"
_USAGE_SAMPLE_HEARTBEAT_KEY = "usage_sample_bg_heartbeat"


def usage_sampling_heartbeat_age_sec() -> float | None:
    """Seconds since the last successful org-wide usage sample, or None if never."""
    from django.core.cache import cache

    stamp = cache.get(_USAGE_SAMPLE_HEARTBEAT_KEY)
    if stamp is None:
        return None
    try:
        return max(0.0, time.time() - float(stamp))
    except (TypeError, ValueError):
        return None


def usage_sampling_is_fresh(*, max_age_sec: float | None = None) -> bool:
    """True when background/cron sampling has written a heartbeat recently."""
    age = usage_sampling_heartbeat_age_sec()
    if age is None:
        return False
    limit = float(
        max_age_sec
        if max_age_sec is not None
        else max(120.0, _usage_sample_interval_sec() * 2.5)
    )
    return age <= limit


def _mark_usage_sampling_heartbeat() -> None:
    from django.core.cache import cache

    # Keep the stamp longer than several missed intervals so pages can detect
    # a dead sampler without false "fresh" readings.
    ttl = max(600, int(_usage_sample_interval_sec() * 10))
    cache.set(_USAGE_SAMPLE_HEARTBEAT_KEY, time.time(), ttl)


def run_usage_sample_all_orgs(*, label: str = "interval") -> dict:
    """
    Persist live PPPoE/Hotspot counters for every organization.

    Runs without anyone viewing usage pages so client/org trend charts keep
    history. One worker wins via cache lock when multiple app processes /
    systemd timers overlap.
    """
    from django.core.cache import cache

    interval = int(_usage_sample_interval_sec())
    # Hold the lock for the whole run so a slow MikroTik fleet cannot overlap
    # with the next timer tick / gunicorn worker.
    lock_ttl = max(180, interval * 3)
    if not cache.add(_USAGE_SAMPLE_LOCK_KEY, 1, timeout=lock_ttl):
        return {
            "ok": True,
            "skipped": True,
            "sampled": 0,
            "organizations": 0,
            "label": label,
        }

    from accounts.models import Organization
    from billing.usage_samples import sample_organization_usage

    sampled_total = 0
    org_count = 0
    try:
        for org in Organization.objects.order_by("id").iterator():
            org_count += 1
            try:
                result = sample_organization_usage(org, force=True)
                sampled_total += int((result or {}).get("sampled") or 0)
            except Exception:
                logger.exception(
                    "usage sample %s failed for org %s",
                    label,
                    getattr(org, "pk", "?"),
                )
            # Refresh lock while walking a large fleet.
            cache.set(_USAGE_SAMPLE_LOCK_KEY, 1, timeout=lock_ttl)
        _mark_usage_sampling_heartbeat()
        if org_count:
            logger.info(
                "usage sample %s: %s org(s), %s new row(s)",
                label,
                org_count,
                sampled_total,
            )
        return {
            "ok": True,
            "skipped": False,
            "sampled": sampled_total,
            "organizations": org_count,
            "label": label,
        }
    finally:
        cache.delete(_USAGE_SAMPLE_LOCK_KEY)


# Back-compat alias for older imports / tests.
_run_usage_sample_all_orgs = run_usage_sample_all_orgs


def ensure_usage_sampling(*, max_age_sec: float | None = None) -> bool:
    """
    If org-wide sampling looks stalled, kick one pass in a daemon thread.

    Used as a safety net from the general-usage page so charts recover when
    the in-process loop or systemd timer has stopped — without blocking the
    request, and without requiring a per-client usage page visit.
    """
    if not _usage_sample_enabled():
        return False
    if usage_sampling_is_fresh(max_age_sec=max_age_sec):
        return False
    from django.core.cache import cache

    # Collapse stampedes when many operators open General usage together.
    if not cache.add("usage_sample_ensure_kick", 1, timeout=45):
        return False

    def _kick() -> None:
        try:
            run_usage_sample_all_orgs(label="ensure")
        except Exception:
            logger.exception("usage sample ensure kick failed")

    threading.Thread(target=_kick, name="usage-sample-ensure", daemon=True).start()
    return True


def _smart_balance_monitor_enabled() -> bool:
    if "--no-smart-balance-monitor" in sys.argv:
        return False
    return os.getenv("SMART_BALANCE_MONITOR_ENABLED", "true").strip().lower() not in {
        "0",
        "false",
        "no",
    }


def _smart_balance_monitor_interval_sec() -> float:
    try:
        return max(45.0, float(os.getenv("SMART_BALANCE_MONITOR_INTERVAL_SEC", "60")))
    except (TypeError, ValueError):
        return 60.0


def _smart_balance_monitor_startup_delay_sec() -> float:
    try:
        return max(0.0, float(os.getenv("SMART_BALANCE_MONITOR_STARTUP_DELAY_SEC", "40")))
    except (TypeError, ValueError):
        return 40.0


_SMART_BALANCE_LOCK_KEY = "smart_balance_monitor_bg_lock"


def run_smart_balance_monitor_fleet(
    *,
    organization_id: int = 0,
    router_id: int = 0,
    rebalance: bool = True,
    workers: int = 4,
    use_lock: bool = True,
    label: str = "interval",
) -> dict:
    """Ping-check smart-balance routers and optionally rebalance heavy clients."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from django.core.cache import cache

    from core.mikrotik_connect import maintain_router_smart_balance
    from core.models import MikroTikRouter
    from core.views import _ports_live_payload, _router_api_host

    interval = int(_smart_balance_monitor_interval_sec())
    lock_ttl = max(180, interval * 3)
    if use_lock and not cache.add(_SMART_BALANCE_LOCK_KEY, 1, timeout=lock_ttl):
        return {
            "ok": True,
            "skipped": True,
            "reason": "locked",
            "label": label,
        }

    qs = MikroTikRouter.objects.filter(
        account_status=MikroTikRouter.AccountStatus.ACTIVE,
        uplink_mode=MikroTikRouter.UplinkMode.SMART_BALANCE,
    ).exclude(host="")
    if organization_id:
        qs = qs.filter(organization_id=organization_id)
    if router_id:
        qs = qs.filter(pk=router_id)

    routers = list(
        qs.only(
            "pk",
            "name",
            "host",
            "username",
            "password",
            "vpn_address",
            "uplink_ports",
            "uplink_weights",
            "wan_interface",
            "bond_interface",
            "smart_auto_balance_enabled",
        )
    )

    ok_count = 0
    moved_total = 0
    slow_total = 0
    errors: list[str] = []
    messages: list[dict[str, str]] = []

    def _maintain(router: MikroTikRouter) -> dict:
        member_ports = [
            str(p).strip() for p in (router.uplink_ports or []) if str(p).strip()
        ]
        if len(member_ports) < 2:
            return {
                "router_id": router.pk,
                "name": router.name,
                "ok": False,
                "skipped": True,
                "reason": "need_two_ports",
            }
        api_host = _router_api_host(router)
        result = maintain_router_smart_balance(
            api_host,
            router.username,
            router.password or "",
            member_ports=member_ports,
            port_weights=(
                dict(router.uplink_weights)
                if isinstance(router.uplink_weights, dict)
                else {}
            ),
            primary_wan=(router.wan_interface or "").strip(),
            bond_interface=(router.bond_interface or "").strip(),
            rebalance=bool(
                rebalance and getattr(router, "smart_auto_balance_enabled", False)
            ),
            router_pk=router.pk,
        )
        result["router_id"] = router.pk
        result["name"] = router.name
        return result

    try:
        if not routers:
            return {
                "ok": True,
                "skipped": False,
                "routers": 0,
                "ok_count": 0,
                "slow_total": 0,
                "moved_total": 0,
                "errors": [],
                "messages": [],
                "label": label,
            }

        worker_count = max(1, min(int(workers or 4), len(routers)))
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            futures = {pool.submit(_maintain, router): router for router in routers}
            for future in as_completed(futures):
                router = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    errors.append(f"{router.name}: {exc}")
                    continue
                if result.get("ok"):
                    ok_count += 1
                    slow_ports = list(
                        (result.get("smart_balance_status") or {}).get("slow_ports")
                        or []
                    )
                    slow_total += len(slow_ports)
                    moved = list((result.get("rebalance") or {}).get("moved") or [])
                    moved_total += len(moved)
                    if moved:
                        from core.client_isp_movements import record_client_isp_movements
                        from core.models import ClientIspMovement

                        rebalance = result.get("rebalance") or {}
                        record_client_isp_movements(
                            router,
                            moved,
                            source=ClientIspMovement.Source.BACKGROUND,
                            seamless=True,
                            imbalance_reason=str(rebalance.get("imbalance_reason") or ""),
                        )
                    monitor = result.get("monitor") or {}
                    if monitor.get("skipped"):
                        messages.append(
                            {
                                "level": "info",
                                "text": (
                                    f"{router.name}: monitor throttled "
                                    f"({monitor.get('reason')})"
                                ),
                            }
                        )
                    elif slow_ports:
                        messages.append(
                            {
                                "level": "warn",
                                "text": (
                                    f"{router.name}: sidelined "
                                    f"{', '.join(slow_ports)}"
                                ),
                            }
                        )
                    if moved:
                        messages.append(
                            {
                                "level": "success",
                                "text": (
                                    f"{router.name}: rebalanced "
                                    f"{len(moved)} client(s)"
                                ),
                            }
                        )
                    try:
                        _ports_live_payload(router)
                    except Exception:
                        pass
                elif result.get("skipped"):
                    messages.append(
                        {
                            "level": "info",
                            "text": (
                                f"{router.name}: skipped "
                                f"({result.get('reason') or 'unknown'})"
                            ),
                        }
                    )
                else:
                    errors.append(
                        f"{router.name}: {result.get('error') or 'maintenance failed'}"
                    )
                if use_lock:
                    cache.set(_SMART_BALANCE_LOCK_KEY, 1, timeout=lock_ttl)

        if routers:
            logger.info(
                "smart balance %s: routers=%s ok=%s sidelined=%s moved=%s",
                label,
                len(routers),
                ok_count,
                slow_total,
                moved_total,
            )
        return {
            "ok": True,
            "skipped": False,
            "routers": len(routers),
            "ok_count": ok_count,
            "slow_total": slow_total,
            "moved_total": moved_total,
            "errors": errors,
            "messages": messages,
            "label": label,
        }
    finally:
        if use_lock:
            cache.delete(_SMART_BALANCE_LOCK_KEY)


def _start_smart_balance_monitor_loop() -> None:
    if not _smart_balance_monitor_enabled():
        logger.info(
            "Smart balance monitor disabled "
            "(SMART_BALANCE_MONITOR_ENABLED=false or --no-smart-balance-monitor)."
        )
        return
    interval = _smart_balance_monitor_interval_sec()

    def _loop() -> None:
        delay = _smart_balance_monitor_startup_delay_sec()
        delay += float(os.getpid() % 7)
        if delay:
            logger.info(
                "Smart balance monitor startup delayed %.0fs so boot traffic stays light.",
                delay,
            )
            time.sleep(delay)
        try:
            run_smart_balance_monitor_fleet(label="startup")
        except Exception:
            logger.exception("smart balance monitor startup failed")
        while True:
            time.sleep(interval)
            try:
                run_smart_balance_monitor_fleet(label="interval")
            except Exception:
                logger.exception("smart balance monitor interval failed")

    threading.Thread(
        target=_loop,
        name="smart-balance-monitor",
        daemon=True,
    ).start()
    logger.info(
        "Smart balance monitor armed (every %.0fs) — ping health; client rebalance "
        "only when smart auto balance is enabled per router. "
        "Disable with SMART_BALANCE_MONITOR_ENABLED=false.",
        interval,
    )


def _start_usage_sample_loop() -> None:
    if not _usage_sample_enabled():
        logger.info(
            "Usage sampling disabled (USAGE_SAMPLE_ENABLED=false or --no-usage-sample)."
        )
        return
    interval = _usage_sample_interval_sec()

    def _loop() -> None:
        delay = _usage_sample_startup_delay_sec()
        # Spread gunicorn workers so they do not all contend for the lock
        # at the same second after a VPS restart / deploy.
        delay += float(os.getpid() % 7)
        if delay:
            logger.info(
                "Usage sampling startup delayed %.0fs so boot traffic stays light.",
                delay,
            )
            time.sleep(delay)
        try:
            run_usage_sample_all_orgs(label="startup")
        except Exception:
            logger.exception("usage sample startup failed")
        while True:
            time.sleep(interval)
            try:
                run_usage_sample_all_orgs(label="interval")
            except Exception:
                logger.exception("usage sample interval failed")

    threading.Thread(
        target=_loop,
        name="usage-sample",
        daemon=True,
    ).start()
    logger.info(
        "Usage sampling armed (every %.0fs) — collects for General usage without "
        "anyone opening client usage pages. Disable with USAGE_SAMPLE_ENABLED=false.",
        interval,
    )


def _expiry_watch_interval_sec() -> float:
    """How often to check customers near their access deadline."""
    try:
        return max(15.0, float(os.getenv("SUBSCRIPTION_EXPIRY_WATCH_INTERVAL_SEC", "30")))
    except (TypeError, ValueError):
        return 30.0


def _run_subscription_sweep(*, label: str = "sweep") -> None:
    from io import StringIO

    from django.core.management import call_command

    out = StringIO()
    try:
        # The management command holds a cross-process lock so only one of
        # gunicorn workers / systemd timer rewrites MikroTiks at a time.
        call_command("sync_subscription_access", stdout=out, stderr=out)
        text = out.getvalue().strip()
        if text:
            logger.info("subscription %s: %s", label, text.splitlines()[-1])
    except Exception:
        logger.exception("subscription %s failed", label)


def _run_near_deadline_expiry_sync() -> None:
    """
    Enforce wall-clock package deadlines and repair PPPoE / Hotspot access leaks.

    Syncs customers near the access cut-off (online or offline) and refreshes
    clock-time Hotspot ``limit-uptime`` from remaining wall-clock time so
    offline periods still consume the prepaid window on the NAS.

    Also repairs:
      - unpaid Hotspot clients that still have WAN (ok-list / app leak)
      - unpaid PPPoE clients still surfing (blocked secret, unpaid live session)
      - paid PPPoE clients dialed without surfing

    Shares the fleet sweep lock with ``sync_subscription_access`` / deploy NAS
    sync so MikroTik rewrites never overlap.
    """
    from billing.services import customers_for_subscription_enforcement_watch
    from core.mikrotik_connect import (
        repair_paid_pppoe_not_surfing_on_router,
        repair_unpaid_hotspot_leaking_on_router,
        repair_unpaid_pppoe_leaking_on_router,
        sync_customer_subscription_access,
    )
    from core.models import MikroTikRouter
    from core.subscription_sync import (
        release_expiry_watch_lock,
        try_acquire_expiry_watch_lock,
    )

    watch_interval = int(_expiry_watch_interval_sec())
    # Hold the shared fleet lock for this short watch pass.
    if not try_acquire_expiry_watch_lock(ttl_sec=max(90, watch_interval * 3)):
        return

    try:
        # past_seconds is wide so a missed tick / lock contention cannot leave
        # an expired client surfing until the next full sweep.
        near = list(
            customers_for_subscription_enforcement_watch(
                past_seconds=600, future_seconds=45
            )
        )
        synced = 0
        for customer in near:
            try:
                # Force session kicks when access must stop — soft sweeps
                # (reauthenticate=False) are for paid limit-uptime refresh only.
                from billing.services import (
                    customer_can_surf_via_hotspot,
                    customer_can_surf_via_pppoe,
                )
                from billing.models import Customer as BillingCustomer

                service = getattr(customer, "service_type", "")
                if service == BillingCustomer.ServiceType.HOTSPOT:
                    must_block = not customer_can_surf_via_hotspot(customer)
                elif service == BillingCustomer.ServiceType.PPPOE:
                    must_block = not customer_can_surf_via_pppoe(customer)
                else:
                    must_block = False
                result = sync_customer_subscription_access(
                    customer,
                    provision=True,
                    reauthenticate=must_block,
                )
                if result.get("ok") or result.get("allowed") is False:
                    synced += 1
            except Exception:
                logger.exception(
                    "near-deadline sync failed for %s",
                    getattr(customer, "account_number", customer.pk),
                )
        if synced:
            logger.info("near-deadline expiry synced %s customer(s)", synced)

        repaired = 0
        hotspot_repaired = 0
        pppoe_leak_repaired = 0
        routers = list(
            MikroTikRouter.objects.filter(
                account_status=MikroTikRouter.AccountStatus.ACTIVE,
            )
            .exclude(host="")
            .select_related("organization")
            .order_by("id")
        )
        if routers:
            from concurrent.futures import ThreadPoolExecutor, as_completed

            def _repair_one_router(router):
                """Run all access repairs for one NAS sequentially (no API races)."""
                results = []
                for fn in (
                    repair_paid_pppoe_not_surfing_on_router,
                    repair_unpaid_pppoe_leaking_on_router,
                    repair_unpaid_hotspot_leaking_on_router,
                ):
                    try:
                        results.append(fn(router))
                    except Exception:
                        logger.exception(
                            "access repair failed router=%s fn=%s",
                            getattr(router, "pk", None),
                            getattr(fn, "__name__", fn),
                        )
                return results

            workers = min(8, len(routers))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [
                    pool.submit(_repair_one_router, router) for router in routers
                ]
                for future in as_completed(futures):
                    try:
                        batch = future.result() or []
                    except Exception:
                        logger.exception("access repair failed")
                        continue
                    for result in batch:
                        count = int(result.get("repaired") or 0)
                        if not count:
                            continue
                        message = result.get("message") or count
                        msg_text = str(message)
                        if "Hotspot leak" in msg_text:
                            hotspot_repaired += count
                            logger.info("unpaid-hotspot leak repair: %s", message)
                        elif "PPPoE leak" in msg_text:
                            pppoe_leak_repaired += count
                            logger.info("unpaid-pppoe leak repair: %s", message)
                        else:
                            repaired += count
                            logger.info("paid-not-surfing repair: %s", message)
        if repaired:
            logger.info("paid-not-surfing repaired %s account(s)", repaired)
        if pppoe_leak_repaired:
            logger.info(
                "unpaid-pppoe leak repaired %s account(s)", pppoe_leak_repaired
            )
        if hotspot_repaired:
            logger.info(
                "unpaid-hotspot leak repaired %s session(s)", hotspot_repaired
            )
    finally:
        release_expiry_watch_lock()


def _start_subscription_sweep_loop() -> None:
    if not _subscription_sweep_enabled():
        return
    interval = _subscription_sweep_interval_sec()
    watch_interval = _expiry_watch_interval_sec()

    def _loop() -> None:
        delay = _subscription_sweep_startup_delay_sec()
        # Spread gunicorn workers so they do not all contend for the sweep lock
        # at the same second after a VPS restart / deploy.
        delay += float(os.getpid() % 11)
        if delay:
            logger.info(
                "Subscription sweep startup delayed %.0fs so pay/recharge is not blocked.",
                delay,
            )
            time.sleep(delay)
        _run_subscription_sweep(label="startup")
        next_full = time.monotonic() + interval
        while True:
            time.sleep(watch_interval)
            try:
                _run_near_deadline_expiry_sync()
            except Exception:
                logger.exception("near-deadline expiry watch failed")
            if time.monotonic() >= next_full:
                _run_subscription_sweep(label="interval")
                next_full = time.monotonic() + interval

    threading.Thread(
        target=_loop,
        name="subscription-sweep",
        daemon=True,
    ).start()
    logger.info(
        "Subscription sweep armed (full every %.0fs, expiry+paid-repair watch every %.0fs). "
        "Disable with SUBSCRIPTION_SWEEP_ENABLED=false.",
        interval,
        watch_interval,
    )


def _sync_wireguard() -> None:
    if not _tunnel_sync_enabled():
        return
    try:
        from core.wireguard import ensure_tunnel_runtime

        ensure_tunnel_runtime()
    except Exception:
        logger.exception("WireGuard startup sync failed")


def _nas_config_pending_path() -> str:
    from pathlib import Path

    from django.conf import settings

    base = Path(getattr(settings, "BASE_DIR", Path.cwd()))
    return str(base / "logs" / ".nas_config_sync_pending")


def _nas_config_sync_requested() -> bool:
    env = os.getenv("NAS_CONFIG_SYNC_ON_BOOT", "").strip().lower()
    if env in {"1", "true", "yes"}:
        return True
    if env in {"0", "false", "no"}:
        return False
    # Only when deploy explicitly opted into a fleet push and left a stamp
    # (see vps_deploy.sh / cpanel_after_pull.sh --sync-nas).
    try:
        return os.path.exists(_nas_config_pending_path())
    except Exception:
        return False


def _run_nas_config_sync_once() -> None:
    """
    One-shot post-deploy NAS push (single winner across gunicorn workers).

    Deploy scripts only leave the pending stamp when NAS sync is opted in.
    Routine code deploys must not rewrite MikroTik firewalls or kick clients.
    """
    if not _nas_config_sync_requested():
        return

    lock_path = _nas_config_pending_path() + ".lock"
    pending = _nas_config_pending_path()
    try:
        os.makedirs(os.path.dirname(pending), exist_ok=True)
        # Exclusive create — only one worker runs the fleet push.
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(lock_fd)
    except FileExistsError:
        return
    except Exception:
        logger.exception("NAS config sync lock failed")
        return

    try:
        from io import StringIO

        from django.core.management import call_command

        # Let WireGuard settle before touching NAS boxes after a service restart.
        try:
            settle = max(
                0.0,
                float(os.getenv("NAS_CONFIG_SYNC_BOOT_DELAY_SEC", "45")),
            )
        except (TypeError, ValueError):
            settle = 45.0
        if settle:
            logger.info(
                "NAS config sync waiting %.0fs after boot (deploy-safe settle).",
                settle,
            )
            time.sleep(settle)

        out = StringIO()
        logger.info("NAS config sync starting (opt-in post-deploy / boot).")
        call_command("sync_nas_config", stdout=out, stderr=out)
        text = out.getvalue().strip()
        if text:
            for line in text.splitlines()[-8:]:
                logger.info("nas-sync: %s", line)
        try:
            if os.path.exists(pending):
                os.remove(pending)
        except Exception:
            pass
    except Exception:
        logger.exception("NAS config sync on boot failed")
    finally:
        try:
            if os.path.exists(lock_path):
                os.remove(lock_path)
        except Exception:
            pass


def start_runtime_tasks() -> None:
    """Idempotent: WireGuard sync, subscription sweep, and usage sampling."""
    global _started
    if _started or not should_start_runtime_tasks():
        return
    _started = True

    def _boot() -> None:
        _sync_wireguard()
        # After the tunnel is up, push any pending *opt-in* post-deploy NAS config.
        try:
            _run_nas_config_sync_once()
        except Exception:
            logger.exception("NAS config sync boot hook failed")
        _start_subscription_sweep_loop()
        _start_usage_sample_loop()
        _start_smart_balance_monitor_loop()

    threading.Thread(target=_boot, name="ispcentric-boot", daemon=True).start()
