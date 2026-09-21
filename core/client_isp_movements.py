"""Persist and query client ISP link movements (manual + auto balance)."""

from __future__ import annotations

from typing import Any

from django.contrib.auth.models import AbstractBaseUser

from core.models import ClientIspMovement, MikroTikRouter


def record_client_isp_movement(
    *,
    router: MikroTikRouter,
    customer_id: int | None = None,
    customer_name: str = "",
    client_ip: str = "",
    from_isp_port: str = "",
    to_isp_port: str = "",
    source: str = ClientIspMovement.Source.MANUAL,
    seamless: bool = True,
    imbalance_reason: str = "",
    actor: AbstractBaseUser | None = None,
) -> ClientIspMovement | None:
    """Best-effort movement log row."""
    to_port = (to_isp_port or "").strip()
    from_port = (from_isp_port or "").strip()
    if not to_port or (from_port and from_port == to_port):
        return None
    org = getattr(router, "organization", None)
    if org is None:
        return None
    try:
        return ClientIspMovement.objects.create(
            organization=org,
            router=router,
            customer_id=customer_id if customer_id else None,
            customer_name=(customer_name or "").strip()[:255],
            client_ip=(client_ip or "").strip()[:45],
            from_isp_port=from_port[:64],
            to_isp_port=to_port[:64],
            source=(source or ClientIspMovement.Source.MANUAL)[:32],
            seamless=bool(seamless),
            imbalance_reason=(imbalance_reason or "").strip()[:32],
            actor=actor if getattr(actor, "pk", None) else None,
        )
    except Exception:
        return None


def record_client_isp_movements(
    router: MikroTikRouter,
    moved: list[dict[str, Any]],
    *,
    source: str = ClientIspMovement.Source.AUTO_REBALANCE,
    seamless: bool = True,
    imbalance_reason: str = "",
    actor: AbstractBaseUser | None = None,
) -> int:
    """Log a batch of moves (auto-rebalance). Returns rows written."""
    count = 0
    for row in moved or []:
        if record_client_isp_movement(
            router=router,
            customer_id=int(row["customer_id"]) if row.get("customer_id") else None,
            customer_name=str(row.get("name") or ""),
            client_ip=str(row.get("client_ip") or row.get("ip") or ""),
            from_isp_port=str(row.get("from_isp") or ""),
            to_isp_port=str(row.get("to_isp") or ""),
            source=source,
            seamless=seamless,
            imbalance_reason=imbalance_reason,
            actor=actor,
        ):
            count += 1
    return count
