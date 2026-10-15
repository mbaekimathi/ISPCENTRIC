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


def _expiry_watch_enabled() -> bool:
    """Near-deadline enforcement — can run without the full subscription sweep."""
    if "--no-sweep" in sys.argv:
        return False
    env = os.getenv("SUBSCRIPTION_EXPIRY_WATCH_ENABLED", "").strip().lower()
    if env in {"0", "false", "no"}:
        return False
    if env in {"1", "true", "yes"}:
        return True
    return _subscription_sweep_enabled()


def _tunnel_sync_enabled() -> bool:
    if "--no-tunnel-sync" in sys.argv:
        return False
    return os.getenv("WIREGUARD_AUTO_SYNC", "true").strip().lower() not in {
        "0",
        "false",
        "no",
    }


def _wireguard_sync_interval_sec() -> float:
    """Re-apply DB peers to wg0 so restarts and manual edits self-heal."""
    try:
        return max(120.0, float(os.getenv("WIREGUARD_SYNC_INTERVAL_SEC", "600")))
    except (TypeError, ValueError):
        return 600.0


def _subscription_sweep_interval_sec() -> float:
    # Prefer aligning with deploy/systemd/ispcentric-sweep.timer (15 min).
    # Full fleet sweeps rewrite NAS state; running them every few minutes was
    # heavy and could flap paid PPPoE for a few seconds. Near-deadline expiry
    # watch still cuts unpaid clients within ~90s.
    try:
        return max(60.0, float(os.getenv("SUBSCRIPTION_SWEEP_INTERVAL_SEC", "900")))
    except (TypeError, ValueError):
        return 900.0


def _paid_repair_enabled() -> bool:
    """
    Soft repair of paid PPPoE (secret/list fix, never kick).

    Default off: frequent paid soft-repair API rewrites were causing brief
    surfing blips. Enable with SUBSCRIPTION_PAID_REPAIR_ENABLED=true when
    diagnosing paid-not-surfing leaks.
    """
    env = os.getenv("SUBSCRIPTION_PAID_REPAIR_ENABLED", "").strip().lower()
    if env in {"1", "true", "yes"}:
        return True
    if env in {"0", "false", "no"}:
        return False
    return False


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
    """How often to snapshot PPPoE/Hotspot usage when nobody has a usage page open."""
    try:
        # Default 10 min. Live charts sample when a usage page is open.
        # This slower pass only keeps fair-usage byte totals moving.
        return max(30.0, float(os.getenv("USAGE_SAMPLE_INTERVAL_SEC", "600")))
    except (TypeError, ValueError):
        return 600.0


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


def _run_usage_sample_all_orgs_body(*, label: str = "interval") -> dict:
    """
    Persist live PPPoE/Hotspot counters for every organization.

    This slow pass keeps fair-usage totals moving when no usage page is open.
    Live charts sample on those pages. One worker wins via cache lock when
    multiple app processes / systemd timers overlap.
    """
    from django.core.cache import cache

    interval = int(_usage_sample_interval_sec())
    heartbeat_age = usage_sampling_heartbeat_age_sec()
    if heartbeat_age is not None and heartbeat_age < max(30.0, interval * 0.75):
        return {
            "ok": True,
            "skipped": True,
            "reason": "external_timer",
            "sampled": 0,
            "organizations": 0,
            "label": label,
        }
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
    from core.subscription_sync import (
        is_fleet_write_active,
        release_fleet_read_lock,
        try_acquire_fleet_read_lock,
    )

    if is_fleet_write_active():
        cache.delete(_USAGE_SAMPLE_LOCK_KEY)
        return {
            "ok": True,
            "skipped": True,
            "reason": "fleet_write",
            "sampled": 0,
            "organizations": 0,
            "label": label,
        }
    if not try_acquire_fleet_read_lock(ttl_sec=lock_ttl, label="usage"):
        cache.delete(_USAGE_SAMPLE_LOCK_KEY)
        return {
            "ok": True,
            "skipped": True,
            "reason": "fleet_read_locked",
            "sampled": 0,
            "organizations": 0,
            "label": label,
        }

    sampled_total = 0
    org_count = 0
    try:
        for org in Organization.objects.order_by("id").iterator():
            org_count += 1
            try:
                result = sample_organization_usage(org, force=False)
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
        release_fleet_read_lock()
        cache.delete(_USAGE_SAMPLE_LOCK_KEY)


def run_usage_sample_all_orgs(*, label: str = "interval") -> dict:
    """Usage sampling is background work and yields the router login to operators."""
    from core.mikrotik_connect import background_mikrotik_work

    with background_mikrotik_work():
        return _run_usage_sample_all_orgs_body(label=label)


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
        "Usage sampling armed (every %.0fs) for fair-usage totals. "
        "Live charts read the router only while a usage page is open. "
        "Disable with USAGE_SAMPLE_ENABLED=false.",
        interval,
    )


def _expiry_watch_interval_sec() -> float:
    """How often to check customers near their access deadline."""
    try:
        return max(15.0, float(os.getenv("SUBSCRIPTION_EXPIRY_WATCH_INTERVAL_SEC", "90")))
    except (TypeError, ValueError):
        return 90.0


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


def _run_urgent_expired_blocks_without_fleet_lock() -> None:
    """
    When the shared fleet lock is held, still push blocks for clients whose
    access deadline has already passed. Skips fleet repair and paid refresh.
    """
    from django.utils import timezone

    from billing.models import Customer as BillingCustomer
    from billing.services import (
        customer_can_surf_via_hotspot,
        customer_can_surf_via_pppoe,
        customer_receives_internet,
        customers_for_subscription_enforcement_watch,
        subscription_access_deadline,
    )
    from core.mikrotik_connect import sync_customer_subscription_access

    now = timezone.now()
    synced = 0
    for customer in customers_for_subscription_enforcement_watch(
        past_seconds=600, future_seconds=0, now=now
    ):
        deadline = subscription_access_deadline(customer)
        if deadline is None or deadline > now:
            continue
        service = getattr(customer, "service_type", "")
        try:
            if service == BillingCustomer.ServiceType.HOTSPOT:
                must_block = not customer_can_surf_via_hotspot(customer)
            elif service == BillingCustomer.ServiceType.PPPOE:
                must_block = not customer_can_surf_via_pppoe(customer)
            elif service == BillingCustomer.ServiceType.STATIC:
                must_block = not customer_receives_internet(customer)
            else:
                continue
            if not must_block:
                continue
            result = sync_customer_subscription_access(
                customer,
                provision=True,
                reauthenticate=True,
            )
            if result.get("ok") or result.get("allowed") is False:
                synced += 1
        except Exception:
            logger.exception(
                "urgent expiry block failed for %s",
                getattr(customer, "account_number", customer.pk),
            )
    if synced:
        logger.info(
            "urgent expiry blocks synced %s customer(s) while fleet lock busy",
            synced,
        )


def _run_near_deadline_expiry_sync() -> None:
    """
    Enforce wall-clock package deadlines and repair PPPoE / Hotspot / Static
    access leaks.

    Syncs customers near the access cut-off (online or offline) and refreshes
    clock-time Hotspot ``limit-uptime`` from remaining wall-clock time so
    offline periods still consume the prepaid window on the NAS.

    Also repairs:
      - unpaid Hotspot clients that still have WAN (ok-list / app leak)
      - unpaid PPPoE clients still surfing (blocked secret, unpaid live session)
      - paid PPPoE clients dialed without surfing

    Shares the fleet sweep lock with ``sync_subscription_access`` / deploy NAS
    sync so MikroTik rewrites never overlap. If the lock is busy, urgent
    already-expired blocks still run without fleet repair.
    """
    from core.subscription_sync import try_acquire_expiry_watch_lock

    watch_interval = int(_expiry_watch_interval_sec())
    # Hold the shared fleet lock for this short watch pass.
    from core.mikrotik_connect import api_timeout_is_busy, background_mikrotik_work

    if not try_acquire_expiry_watch_lock(ttl_sec=max(90, watch_interval * 3)):
        # Fleet writer busy — still cut already-expired clients so a long sweep
        # cannot leave unpaid sessions surfing until the next free lock.
        with background_mikrotik_work():
            _run_urgent_expired_blocks_without_fleet_lock()
        return

    with background_mikrotik_work():
        _run_near_deadline_expiry_sync_locked(
            api_timeout_is_busy=api_timeout_is_busy,
        )


def _run_near_deadline_expiry_sync_locked(*, api_timeout_is_busy) -> None:
    from billing.services import customers_for_subscription_enforcement_watch
    from core.mikrotik_connect import (
        repair_router_access_leaks_on_router,
        sync_customer_subscription_access,
    )
    from core.models import MikroTikRouter
    from core.subscription_sync import release_expiry_watch_lock

    try:
        from django.core.cache import cache
        from django.utils import timezone

        from billing.services import subscription_access_deadline

        # past_seconds is wide so a missed tick / lock contention cannot leave
        # an expired client surfing until the next full sweep.
        near = list(
            customers_for_subscription_enforcement_watch(
                past_seconds=600, future_seconds=45
            )
        )
        now = timezone.now()
        urgent_deadline = False
        for customer in near:
            deadline = subscription_access_deadline(customer)
            if deadline is None:
                continue
            delta = (deadline - now).total_seconds()
            if delta <= 90:
                urgent_deadline = True
                break
        repair_tick = int(cache.get("expiry_watch_repair_tick") or 0) + 1
        cache.set("expiry_watch_repair_tick", repair_tick, 3600)
        # Unpaid leaks stay frequent. Paid soft repair is off by default —
        # when enabled it runs rarely so surfing CPEs are not API-hammered.
        run_unpaid_repair = urgent_deadline or (repair_tick % 3 == 0)
        run_paid_repair = _paid_repair_enabled() and (repair_tick % 20 == 0)
        run_fleet_repair = run_unpaid_repair or run_paid_repair
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
                elif service == BillingCustomer.ServiceType.STATIC:
                    from billing.services import customer_receives_internet

                    must_block = not customer_receives_internet(customer)
                else:
                    must_block = False
                result = sync_customer_subscription_access(
                    customer,
                    provision=True,
                    reauthenticate=must_block,
                )
                if result.get("ok") or result.get("allowed") is False:
                    synced += 1
            except TimeoutError as exc:
                if not api_timeout_is_busy(exc):
                    logger.exception(
                        "near-deadline sync failed for %s",
                        getattr(customer, "account_number", customer.pk),
                    )
            except Exception:
                logger.exception(
                    "near-deadline sync failed for %s",
                    getattr(customer, "account_number", customer.pk),
                )
        if synced:
            logger.info("near-deadline expiry synced %s customer(s)", synced)

        try:
            from core.mikrotik_connect import process_hotspot_block_pending_fleet

            pending = process_hotspot_block_pending_fleet()
            drained = int(pending.get("drained") or 0)
            remaining = int(pending.get("remaining") or 0)
            if drained:
                logger.info(
                    "hotspot pending pay-wall blocks drained=%s remaining=%s",
                    drained,
                    remaining,
                )
        except Exception:
            logger.exception("hotspot pending block drain failed")

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
        if routers and run_fleet_repair:
            from concurrent.futures import ThreadPoolExecutor, as_completed

            def _repair_one_router(router):
                """Run all access repairs for one NAS sequentially (no API races)."""
                from core.mikrotik_connect import (
                    background_mikrotik_work,
                    is_mikrotik_host_cooling_down,
                )
                from core.views import _resolve_working_nas_host

                with background_mikrotik_work():
                    api_host = _resolve_working_nas_host(router, timeout=0.8)
                    if is_mikrotik_host_cooling_down(api_host):
                        return []
                    try:
                        return repair_router_access_leaks_on_router(
                            router,
                            repair_paid=run_paid_repair,
                            repair_unpaid=run_unpaid_repair,
                        )
                    except TimeoutError as exc:
                        if api_timeout_is_busy(exc):
                            return []
                        logger.exception(
                            "access repair failed router=%s",
                            getattr(router, "pk", None),
                        )
                        return []
                    except Exception:
                        logger.exception(
                            "access repair failed router=%s",
                            getattr(router, "pk", None),
                        )
                        return []

            workers = min(4, len(routers))
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
    sweep_enabled = _subscription_sweep_enabled()
    watch_enabled = _expiry_watch_enabled()
    if not sweep_enabled and not watch_enabled:
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
        if sweep_enabled:
            _run_subscription_sweep(label="startup")
        next_full = time.monotonic() + interval if sweep_enabled else 0.0
        while True:
            time.sleep(watch_interval)
            if watch_enabled:
                try:
                    _run_near_deadline_expiry_sync()
                except Exception:
                    logger.exception("near-deadline expiry watch failed")
            if sweep_enabled and time.monotonic() >= next_full:
                _run_subscription_sweep(label="interval")
                next_full = time.monotonic() + interval

    threading.Thread(
        target=_loop,
        name="subscription-sweep",
        daemon=True,
    ).start()
    if sweep_enabled and watch_enabled:
        logger.info(
            "Subscription sweep armed (full every %.0fs, expiry watch every %.0fs). "
            "Disable sweep with SUBSCRIPTION_SWEEP_ENABLED=false; "
            "watch alone with SUBSCRIPTION_EXPIRY_WATCH_ENABLED=true.",
            interval,
            watch_interval,
        )
    elif sweep_enabled:
        logger.info(
            "Subscription sweep armed (full every %.0fs). "
            "Disable with SUBSCRIPTION_SWEEP_ENABLED=false.",
            interval,
        )
    else:
        logger.info(
            "Expiry watch armed (every %.0fs, no in-process full sweep). "
            "Disable with SUBSCRIPTION_EXPIRY_WATCH_ENABLED=false.",
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


def _start_wireguard_sync_loop() -> None:
    if not _tunnel_sync_enabled():
        return
    try:
        from core.wireguard import configured

        if not configured():
            return
    except Exception:
        return

    interval = _wireguard_sync_interval_sec()

    def _loop() -> None:
        delay = 45.0 + float(os.getpid() % 25)
        time.sleep(delay)
        while True:
            try:
                from core.wireguard import ensure_tunnel_runtime

                ensure_tunnel_runtime()
            except Exception:
                logger.exception("WireGuard periodic sync failed")
            time.sleep(interval)

    threading.Thread(target=_loop, name="wireguard-sync", daemon=True).start()
    logger.info(
        "WireGuard peer re-sync armed (every %.0fs). Disable with WIREGUARD_AUTO_SYNC=false.",
        interval,
    )


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


_background_started = False
_background_guard = threading.Lock()
_BACKGROUND_OWNER_KEY = "ispcentric_background_owner"


def _jobs_cache():
    from django.core.cache import caches

    return caches["jobs"]


def _claim_background_owner() -> bool:
    """One process runs sweep, usage sampling, and tunnel sync."""
    from core.subscription_sync import _pid_is_alive

    cache = _jobs_cache()
    pid = os.getpid()
    try:
        if cache.add(_BACKGROUND_OWNER_KEY, pid, timeout=180):
            return True
        holder = cache.get(_BACKGROUND_OWNER_KEY)
        try:
            holder_pid = int(holder or 0)
        except (TypeError, ValueError):
            holder_pid = 0
        if holder_pid == pid:
            cache.set(_BACKGROUND_OWNER_KEY, pid, timeout=180)
            return True
        if holder_pid and not _pid_is_alive(holder_pid):
            cache.delete(_BACKGROUND_OWNER_KEY)
            return bool(cache.add(_BACKGROUND_OWNER_KEY, pid, timeout=180))
    except Exception:
        logger.exception("background owner claim failed")
    return False


def _ensure_background_loops() -> None:
    """Start the heavy loops once, and only in the process that owns them."""
    global _background_started
    with _background_guard:
        if _background_started:
            try:
                cache = _jobs_cache()
                holder = cache.get(_BACKGROUND_OWNER_KEY)
                try:
                    holder_pid = int(holder or 0)
                except (TypeError, ValueError):
                    holder_pid = 0
                if holder_pid == os.getpid():
                    cache.set(_BACKGROUND_OWNER_KEY, os.getpid(), timeout=180)
            except Exception:
                pass
            return
        if not _claim_background_owner():
            return
        _background_started = True
    logger.info("This process owns MikroTik background work (pid %s).", os.getpid())
    _sync_wireguard()
    _start_wireguard_sync_loop()
    try:
        _run_nas_config_sync_once()
    except Exception:
        logger.exception("NAS config sync boot hook failed")
    _start_subscription_sweep_loop()
    _start_usage_sample_loop()


def start_runtime_tasks() -> None:
    """Idempotent: one worker owns WireGuard sync, sweeps, and usage sampling."""
    global _started
    if _started or not should_start_runtime_tasks():
        return
    _started = True

    def _watch() -> None:
        while True:
            try:
                _ensure_background_loops()
            except Exception:
                logger.exception("background owner watch failed")
            time.sleep(60)

    threading.Thread(target=_watch, name="ispcentric-boot", daemon=True).start()
