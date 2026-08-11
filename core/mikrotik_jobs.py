"""Track MikroTik background push jobs (hosted deployments)."""

from __future__ import annotations

import logging
from typing import Any

from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger(__name__)

JOB_TTL = 3600
JOB_TYPES = (
    "credentials",
    "wifi",
    "clean_uplink",
    "port_toggle",
    "port_role",
    "uplink_bond",
    "uplink_failover",
    "uplink_balance",
    "pppoe_push",
    "hotspot_push",
)


def job_cache_key(router_id: int, job_type: str) -> str:
    return f"mikrotik_job:{router_id}:{job_type}"


def set_job(
    router_id: int,
    job_type: str,
    status: str,
    *,
    message: str = "",
    error: str = "",
) -> None:
    """status: pending | running | ok | failed"""
    cache.set(
        job_cache_key(router_id, job_type),
        {
            "status": status,
            "message": message,
            "error": error,
            "updated_at": timezone.now().isoformat(),
        },
        JOB_TTL,
    )


def get_job(router_id: int, job_type: str) -> dict[str, Any] | None:
    payload = cache.get(job_cache_key(router_id, job_type))
    return payload if isinstance(payload, dict) else None


def get_router_jobs(router_id: int) -> dict[str, dict[str, Any]]:
    jobs: dict[str, dict[str, Any]] = {}
    for job_type in JOB_TYPES:
        payload = get_job(router_id, job_type)
        if payload:
            jobs[job_type] = payload
    return jobs


def clear_job(router_id: int, job_type: str) -> None:
    cache.delete(job_cache_key(router_id, job_type))
