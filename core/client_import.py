"""Guided spreadsheet import for PPPoE clients."""

from __future__ import annotations

import csv
import io
import logging
import re
import secrets
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from django.db import IntegrityError, transaction
from django.http import HttpResponse
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime

from billing.models import BillingPlan, Customer
from billing.services import (
    compute_package_end,
    customer_phone_is_taken,
    generate_account_number_from_phone,
)
from core.models import MikroTikRouter

logger = logging.getLogger(__name__)

IMPORT_SESSION_KEY = "client_import_draft"
IMPORT_MAX_ROWS = 2000

# System fields users can map spreadsheet columns onto.
IMPORT_FIELDS: tuple[dict[str, Any], ...] = (
    {
        "key": "full_name",
        "label": "Full name",
        "required": True,
        "help": "Client’s display name",
        "aliases": (
            "full name",
            "fullname",
            "client name",
            "customer name",
            "subscriber",
            "client",
            "customer",
        ),
    },
    {
        "key": "phone",
        "label": "Phone",
        "required": True,
        "help": "Mobile number (used for account number when blank)",
        "aliases": (
            "phone",
            "mobile",
            "telephone",
            "tel",
            "msisdn",
            "contact",
            "phone number",
            "cellphone",
        ),
    },
    {
        "key": "email",
        "label": "Email",
        "required": False,
        "help": "Optional email address",
        "aliases": ("email", "e-mail", "mail"),
    },
    {
        "key": "account_number",
        "label": "Account number",
        "required": False,
        "help": "Leave blank to auto-generate from phone",
        "aliases": ("account number", "account", "acct", "account no", "account #"),
    },
    {
        "key": "pppoe_username",
        "label": "PPPoE username",
        "required": False,
        "help": "Defaults to phone when blank",
        "aliases": (
            "pppoe username",
            "username",
            "user name",
            "login",
            "pppoe user",
            "secret name",
        ),
    },
    {
        "key": "pppoe_password",
        "label": "PPPoE password",
        "required": False,
        "help": "Auto-generated when blank",
        "aliases": (
            "pppoe password",
            "password",
            "pass",
            "secret",
            "pppoe pass",
            "dial password",
        ),
    },
    {
        "key": "plan",
        "label": "Package / plan",
        "required": False,
        "help": "Package name — use a default below if your file has none",
        "aliases": (
            "package",
            "plan",
            "billing plan",
            "package name",
            "plan name",
            "speed",
            "profile",
        ),
    },
    {
        "key": "mikrotik",
        "label": "MikroTik",
        "required": False,
        "help": "Router name or host/IP — use a default below if missing",
        "aliases": (
            "mikrotik",
            "mikrotik name",
            "router",
            "router name",
            "nas",
            "nas name",
            "mikrotik host",
            "host",
        ),
    },
    {
        "key": "address",
        "label": "Location / address",
        "required": False,
        "help": "Place or street address",
        "aliases": ("location", "address", "place", "area", "estate"),
    },
    {
        "key": "building_name",
        "label": "Building",
        "required": False,
        "help": "Building or apartment block",
        "aliases": ("building", "building name", "block", "apartment"),
    },
    {
        "key": "house_number",
        "label": "House number",
        "required": False,
        "help": "House / unit number",
        "aliases": ("house number", "house", "unit", "door", "flat"),
    },
    {
        "key": "cpe_ip",
        "label": "CPE IP",
        "required": False,
        "help": "Client router LAN IP (optional)",
        "aliases": ("cpe ip", "router ip", "client ip", "ip"),
    },
    {
        "key": "cpe_username",
        "label": "CPE username",
        "required": False,
        "help": "Defaults from MikroTik settings or admin",
        "aliases": ("cpe username", "cpe user", "router username", "winbox user"),
    },
    {
        "key": "cpe_password",
        "label": "CPE password",
        "required": False,
        "help": "Defaults from MikroTik client-router password",
        "aliases": ("cpe password", "cpe pass", "router password", "winbox password"),
    },
    {
        "key": "status",
        "label": "Status",
        "required": False,
        "help": "active / queued / installed — default is queued for install",
        "aliases": ("status", "state", "account status"),
    },
    {
        "key": "package_start",
        "label": "Package start",
        "required": False,
        "help": "Only used when status is active",
        "aliases": ("package start", "start date", "activated", "activation date"),
    },
    {
        "key": "package_end",
        "label": "Package end",
        "required": False,
        "help": "Computed from plan when blank and status is active",
        "aliases": ("package end", "end date", "expiry", "expires", "expiry date"),
    },
)

_FIELD_BY_KEY = {f["key"]: f for f in IMPORT_FIELDS}

_STATUS_MAP = {
    "active": Customer.Status.ACTIVE,
    "activated": Customer.Status.ACTIVE,
    "live": Customer.Status.ACTIVE,
    "online": Customer.Status.ACTIVE,
    "queued": Customer.Status.QUEUED,
    "queue": Customer.Status.QUEUED,
    "pending": Customer.Status.QUEUED,
    "new": Customer.Status.QUEUED,
    "installed": Customer.Status.INSTALLED,
    "install": Customer.Status.INSTALLED,
    "suspended": Customer.Status.SUSPENDED,
    "suspend": Customer.Status.SUSPENDED,
    "blocked": Customer.Status.SUSPENDED,
}


@dataclass
class ParsedSpreadsheet:
    filename: str
    headers: list[str]
    rows: list[list[str]]
    sheet_name: str = ""


def _norm_header(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = text.replace("_", " ").replace("-", " ")
    text = re.sub(r"\s+", " ", text)
    return text


def _cell_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat(sep=" ", timespec="seconds")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip()


def _default_password(length: int = 10) -> str:
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789ACDEFGHJKLMNPQRSTUVWXYZ"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def suggest_column_mapping(headers: list[str]) -> dict[str, int | None]:
    """Map each system field key → source column index (or None)."""
    normalized = [_norm_header(h) for h in headers]
    used: set[int] = set()
    mapping: dict[str, int | None] = {field["key"]: None for field in IMPORT_FIELDS}

    # Pass 1: exact header matches (strongest).
    for field in IMPORT_FIELDS:
        aliases = {_norm_header(field["label"]), *(_norm_header(a) for a in field["aliases"])}
        for idx, header in enumerate(normalized):
            if idx in used or not header:
                continue
            if header in aliases:
                mapping[field["key"]] = idx
                used.add(idx)
                break

    # Pass 2: longer alias contained in header (or header contained in alias).
    for field in IMPORT_FIELDS:
        if mapping[field["key"]] is not None:
            continue
        aliases = {
            a
            for a in (
                _norm_header(field["label"]),
                *(_norm_header(x) for x in field["aliases"]),
            )
            if len(a) >= 5
        }
        for idx, header in enumerate(normalized):
            if idx in used or not header or len(header) < 4:
                continue
            if any(alias in header or header in alias for alias in aliases):
                mapping[field["key"]] = idx
                used.add(idx)
                break

    return mapping


def parse_upload(uploaded_file) -> ParsedSpreadsheet:
    """Parse .xlsx / .xls / .csv into headers + string rows."""
    name = (getattr(uploaded_file, "name", None) or "upload").strip()
    lower = name.lower()
    raw = uploaded_file.read()
    if not raw:
        raise ValueError("The uploaded file is empty.")

    if lower.endswith((".xlsx", ".xlsm", ".xltx", ".xltm")) or raw[:2] == b"PK":
        return _parse_xlsx(raw, filename=name)
    if lower.endswith(".csv") or lower.endswith(".txt"):
        return _parse_csv(raw, filename=name)
    # Try Excel first, then CSV.
    try:
        return _parse_xlsx(raw, filename=name)
    except Exception:
        return _parse_csv(raw, filename=name)


def _parse_xlsx(raw: bytes, *, filename: str) -> ParsedSpreadsheet:
    from openpyxl import load_workbook

    wb = load_workbook(io.BytesIO(raw), read_only=True, data_only=True)
    ws = wb.active
    sheet_name = ws.title or "Sheet1"
    matrix: list[list[str]] = []
    for row in ws.iter_rows(values_only=True):
        values = [_cell_str(cell) for cell in row]
        if any(values):
            matrix.append(values)
    wb.close()
    if not matrix:
        raise ValueError("No rows found in the spreadsheet.")
    headers = matrix[0]
    body = matrix[1:]
    if len(body) > IMPORT_MAX_ROWS:
        raise ValueError(f"Too many rows (max {IMPORT_MAX_ROWS}). Split the file and try again.")
    # Normalize row widths to header length.
    width = len(headers)
    rows = [(r + [""] * width)[:width] for r in body]
    return ParsedSpreadsheet(filename=filename, headers=headers, rows=rows, sheet_name=sheet_name)


def _parse_csv(raw: bytes, *, filename: str) -> ParsedSpreadsheet:
    text = None
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        raise ValueError("Could not read the CSV file encoding.")
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(text), dialect)
    matrix = [[_cell_str(cell) for cell in row] for row in reader if any(_cell_str(c) for c in row)]
    if not matrix:
        raise ValueError("No rows found in the CSV file.")
    headers = matrix[0]
    body = matrix[1:]
    if len(body) > IMPORT_MAX_ROWS:
        raise ValueError(f"Too many rows (max {IMPORT_MAX_ROWS}). Split the file and try again.")
    width = len(headers)
    rows = [(r + [""] * width)[:width] for r in body]
    return ParsedSpreadsheet(filename=filename, headers=headers, rows=rows, sheet_name="CSV")


def import_template_response() -> HttpResponse:
    """Blank Excel template matching the recommended import columns."""
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill
    from openpyxl.utils import get_column_letter

    headers = [
        "Full name",
        "Phone",
        "Email",
        "PPPoE username",
        "PPPoE password",
        "Package",
        "MikroTik",
        "Location",
        "Building",
        "House number",
        "Account number",
        "Status",
    ]
    example = [
        "Jane Wanjiku",
        "0712345678",
        "jane@example.com",
        "0712345678",
        "",
        "Home 10Mbps",
        "Tower A",
        "Kilimani",
        "Sunrise Flats",
        "B12",
        "",
        "queued",
    ]
    wb = Workbook()
    ws = wb.active
    ws.title = "Clients"
    ws.append(headers)
    ws.append(example)
    fill = PatternFill("solid", fgColor="0D9488")
    font = Font(bold=True, color="FFFFFF")
    for idx in range(1, len(headers) + 1):
        cell = ws.cell(1, idx)
        cell.fill = fill
        cell.font = font
        ws.column_dimensions[get_column_letter(idx)].width = 16
    notes = wb.create_sheet("Instructions")
    notes["A1"] = "How to use this template"
    notes["A1"].font = Font(bold=True, size=14)
    lines = [
        "1. Keep the header row (row 1) — rename columns only if you must.",
        "2. Add one client per row.",
        "3. Full name and Phone are required.",
        "4. Leave PPPoE password blank to auto-generate.",
        "5. Leave Account number blank to auto-generate from phone.",
        "6. Package and MikroTik can be set as defaults on the import page if your file lacks them.",
        "7. Status: queued (default), installed, or active.",
        "8. Save as .xlsx and upload on the Import clients page.",
        "9. CSV works too — same column names.",
        "10. You can also upload exports from other billing systems; map columns on the next step.",
    ]
    for i, line in enumerate(lines, start=3):
        notes[f"A{i}"] = line
    notes.column_dimensions["A"].width = 100

    buf = io.BytesIO()
    wb.save(buf)
    response = HttpResponse(
        buf.getvalue(),
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    response["Content-Disposition"] = (
        'attachment; filename="ispcentric-clients-import-template.xlsx"'
    )
    response["Cache-Control"] = "no-store"
    return response


def draft_to_session(parsed: ParsedSpreadsheet) -> dict[str, Any]:
    return {
        "filename": parsed.filename,
        "sheet_name": parsed.sheet_name,
        "headers": parsed.headers,
        "rows": parsed.rows,
        "suggested": suggest_column_mapping(parsed.headers),
    }


def _mapped_value(row: list[str], mapping: dict[str, int | None], key: str) -> str:
    idx = mapping.get(key)
    if idx is None:
        return ""
    try:
        idx_i = int(idx)
    except (TypeError, ValueError):
        return ""
    if idx_i < 0 or idx_i >= len(row):
        return ""
    return (row[idx_i] or "").strip()


def _parse_when(value: str):
    text = (value or "").strip()
    if not text:
        return None
    dt = parse_datetime(text.replace("Z", "+00:00"))
    if dt is not None:
        if timezone.is_naive(dt):
            return timezone.make_aware(dt, timezone.get_current_timezone())
        return timezone.localtime(dt)
    d = parse_date(text[:10]) if len(text) >= 8 else parse_date(text)
    if d is not None:
        return timezone.make_aware(
            datetime.combine(d, datetime.min.time()),
            timezone.get_current_timezone(),
        )
    # Excel-ish day/month/year
    for fmt in ("%d/%m/%Y", "%d-%m-%Y", "%m/%d/%Y", "%Y/%m/%d", "%d/%m/%y"):
        try:
            parsed = datetime.strptime(text[:19], fmt)
            return timezone.make_aware(parsed, timezone.get_current_timezone())
        except ValueError:
            continue
    return None


def _resolve_plan(org, name: str, *, default_plan=None):
    label = (name or "").strip()
    if not label:
        return default_plan
    qs = BillingPlan.objects.filter(
        organization=org,
        service_type=BillingPlan.ServiceType.PPPOE,
        is_active=True,
    )
    exact = qs.filter(name__iexact=label).first()
    if exact:
        return exact
    soft = qs.filter(name__icontains=label).order_by("name").first()
    return soft or default_plan


def _resolve_router(org, name: str, *, default_router=None):
    label = (name or "").strip()
    if not label:
        return default_router
    qs = MikroTikRouter.objects.filter(organization=org)
    exact = qs.filter(name__iexact=label).first()
    if exact:
        return exact
    by_host = qs.filter(host__iexact=label).first()
    if by_host:
        return by_host
    soft = qs.filter(name__icontains=label).order_by("name").first()
    if soft:
        return soft
    soft_host = qs.filter(host__icontains=label).order_by("name").first()
    return soft_host or default_router


def _resolve_status(raw: str) -> str:
    key = (raw or "").strip().lower()
    if not key:
        return Customer.Status.QUEUED
    if key in _STATUS_MAP:
        return _STATUS_MAP[key]
    for choice, _label in Customer.Status.choices:
        if key == choice or key == _label.lower():
            return choice
    return Customer.Status.QUEUED


def preview_mapped_rows(
    draft: dict[str, Any],
    mapping: dict[str, int | None],
    *,
    limit: int = 8,
) -> list[dict[str, str]]:
    rows = draft.get("rows") or []
    out = []
    for row in rows[:limit]:
        out.append(
            {
                key: _mapped_value(row, mapping, key)
                for key in _FIELD_BY_KEY
            }
        )
    return out


def run_client_import(
    org,
    draft: dict[str, Any],
    mapping: dict[str, int | None],
    *,
    default_router=None,
    default_plan=None,
    registered_by=None,
) -> dict[str, Any]:
    """Create PPPoE clients from a mapped draft. Returns summary + row errors."""
    if not org:
        raise ValueError("Organization is required.")
    if mapping.get("full_name") is None:
        raise ValueError("Map a column to Full name.")
    if mapping.get("phone") is None:
        raise ValueError("Map a column to Phone.")

    routers = list(MikroTikRouter.objects.filter(organization=org))
    plans = list(
        BillingPlan.objects.filter(
            organization=org,
            service_type=BillingPlan.ServiceType.PPPOE,
            is_active=True,
        )
    )
    if default_router is None and len(routers) == 1:
        default_router = routers[0]
    if default_plan is None and len(plans) == 1:
        default_plan = plans[0]

    created = 0
    skipped = 0
    errors: list[dict[str, Any]] = []
    created_names: list[str] = []

    for index, row in enumerate(draft.get("rows") or [], start=2):
        raw = {key: _mapped_value(row, mapping, key) for key in _FIELD_BY_KEY}
        full_name = (raw["full_name"] or "").strip().upper()
        phone = (raw["phone"] or "").strip().upper()
        if not full_name and not phone:
            skipped += 1
            continue
        if not full_name:
            errors.append({"row": index, "error": "Missing full name."})
            continue
        if not phone:
            errors.append({"row": index, "error": "Missing phone number.", "name": full_name})
            continue

        if customer_phone_is_taken(org, phone):
            errors.append(
                {
                    "row": index,
                    "error": "Phone already registered for this ISP.",
                    "name": full_name,
                    "phone": phone,
                }
            )
            continue

        router = _resolve_router(org, raw["mikrotik"], default_router=default_router)
        plan = _resolve_plan(org, raw["plan"], default_plan=default_plan)
        if plan is None:
            errors.append(
                {
                    "row": index,
                    "error": "No package matched — set a default package or add a Package column.",
                    "name": full_name,
                }
            )
            continue
        if router is None:
            errors.append(
                {
                    "row": index,
                    "error": "No MikroTik matched — set a default MikroTik or add a MikroTik column.",
                    "name": full_name,
                }
            )
            continue
        if not plan.is_available_on_router(router):
            errors.append(
                {
                    "row": index,
                    "error": f'Package "{plan.name}" is not linked to MikroTik "{router.name}".',
                    "name": full_name,
                }
            )
            continue

        username = (raw["pppoe_username"] or "").strip().upper() or phone
        if Customer.objects.filter(
            organization=org,
            service_type=Customer.ServiceType.PPPOE,
            pppoe_username__iexact=username,
        ).exists():
            errors.append(
                {
                    "row": index,
                    "error": f'PPPoE username "{username}" already exists.',
                    "name": full_name,
                }
            )
            continue

        password = (raw["pppoe_password"] or "").strip() or _default_password()
        account_number = (raw["account_number"] or "").strip()
        if account_number and Customer.objects.filter(account_number=account_number).exists():
            errors.append(
                {
                    "row": index,
                    "error": f'Account number "{account_number}" already exists.',
                    "name": full_name,
                }
            )
            continue
        if not account_number:
            account_number = generate_account_number_from_phone(phone, organization=org)

        status = _resolve_status(raw["status"])
        package_start = _parse_when(raw["package_start"])
        package_end = _parse_when(raw["package_end"])
        if status == Customer.Status.ACTIVE:
            if package_start is None:
                package_start = timezone.now()
            if package_end is None and plan is not None:
                package_end = compute_package_end(package_start, plan)
        else:
            # Queued / installed imports wait for activation — clear package clock.
            if status in {
                Customer.Status.QUEUED,
                Customer.Status.INSTALLED,
                Customer.Status.ASSIGNED,
                Customer.Status.LEAD,
            }:
                package_start = None
                package_end = None

        cpe_username = (raw["cpe_username"] or "").strip() or (
            getattr(router, "default_cpe_username", None) or "admin"
        )
        cpe_password = (raw["cpe_password"] or "").strip() or (
            getattr(router, "default_cpe_password", None) or ""
        )

        try:
            with transaction.atomic():
                customer = Customer(
                    organization=org,
                    full_name=full_name,
                    phone=phone,
                    email=(raw["email"] or "").strip().lower(),
                    address=(raw["address"] or "").strip().upper(),
                    building_name=(raw["building_name"] or "").strip().upper(),
                    house_number=(raw["house_number"] or "").strip().upper(),
                    account_number=account_number,
                    service_type=Customer.ServiceType.PPPOE,
                    pppoe_username=username,
                    pppoe_password=password,
                    cpe_username=cpe_username,
                    cpe_password=cpe_password,
                    cpe_ip=(raw["cpe_ip"] or "").strip(),
                    plan=plan,
                    router=router,
                    status=status,
                    package_start=package_start,
                    package_end=package_end,
                    registered_by=registered_by,
                )
                customer.save()
        except IntegrityError as exc:
            errors.append(
                {
                    "row": index,
                    "error": str(exc) or "Could not save this row (duplicate?).",
                    "name": full_name,
                    "phone": phone,
                }
            )
            continue
        except Exception as exc:  # noqa: BLE001 — collect per-row failures
            logger.exception("Client import failed on row %s", index)
            errors.append(
                {
                    "row": index,
                    "error": str(exc) or "Unexpected error on this row.",
                    "name": full_name,
                }
            )
            continue

        created += 1
        if len(created_names) < 12:
            created_names.append(full_name)

    return {
        "created": created,
        "skipped": skipped,
        "failed": len(errors),
        "errors": errors[:80],
        "created_names": created_names,
        "total_rows": len(draft.get("rows") or []),
    }
