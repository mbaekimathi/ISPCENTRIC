from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q, Sum
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_POST

from accounts.routing import home_url_for_user, is_viewing_as_client
from core.views import client_page_context, resolve_organization

from .forms import BillingPackageRegisterForm
from .models import BillingPlan, Customer, Invoice, Payment, StkPushRequest
from .services import customers_needing_renewal_attention
from .stk import refresh_stk_status, start_subscription_stk_payment


def _require_client_workspace(request):
    employee = getattr(request.user, "employee_profile", None)
    viewing_client = bool(employee and is_viewing_as_client(request, employee))
    if employee is not None and not viewing_client:
        return redirect(home_url_for_user(request.user, request))
    return None


def _handle_register_package(request, org, *, success_url_name: str):
    """Process package registration POST. Returns (form, open_modal, response_or_none)."""
    form = BillingPackageRegisterForm(organization=org)
    open_modal = ""
    if request.method != "POST":
        return form, open_modal, None

    action = (request.POST.get("action") or "").strip()
    if action != "register_package":
        return form, open_modal, None

    if not org:
        messages.error(request, "No organization is linked to this workspace.")
        return form, open_modal, redirect(success_url_name)

    form = BillingPackageRegisterForm(request.POST, request.FILES, organization=org)
    if form.is_valid():
        plan = form.save()
        messages.success(
            request,
            f"Package “{plan.name}” registered ({plan.speed_label} · {plan.get_duration_display()}).",
        )
        return form, open_modal, redirect(success_url_name)

    return form, "billing-package-modal", None


def _handle_edit_package(request, org, *, success_url_name: str):
    """Process package edit POST. Returns (form, open_modal, response_or_none)."""
    form = BillingPackageRegisterForm(organization=org, id_prefix="edit_package")
    open_modal = ""
    if request.method != "POST":
        return form, open_modal, None

    action = (request.POST.get("action") or "").strip()
    if action != "edit_package":
        return form, open_modal, None

    if not org:
        messages.error(request, "No organization is linked to this workspace.")
        return form, open_modal, redirect(success_url_name)

    package_id = (request.POST.get("package_id") or "").strip()
    if not package_id.isdigit():
        messages.error(request, "Choose a package to edit.")
        return form, open_modal, redirect(success_url_name)

    plan = get_object_or_404(BillingPlan, pk=int(package_id), organization=org)
    previous_download = int(plan.download_speed_mbps or 0)
    previous_upload = int(plan.upload_speed_mbps or 0)
    form = BillingPackageRegisterForm(
        request.POST,
        request.FILES,
        organization=org,
        instance=plan,
        id_prefix="edit_package",
    )
    if form.is_valid():
        plan = form.save()
        speeds_changed = (
            int(plan.download_speed_mbps or 0) != previous_download
            or int(plan.upload_speed_mbps or 0) != previous_upload
        )
        if speeds_changed:
            _reprovision_customers_for_plan_speeds(plan)
        messages.success(
            request,
            f"Package “{plan.name}” updated ({plan.speed_label} · {plan.get_duration_display()}).",
        )
        return form, open_modal, redirect(success_url_name)

    return form, "billing-package-edit-modal", None


def _reprovision_customers_for_plan_speeds(plan) -> int:
    """Push updated package Mbps onto every assigned customer's NAS profile."""
    if plan is None:
        return 0
    try:
        from core.mikrotik_connect import sync_customer_subscription_access
    except Exception:
        return 0

    updated = 0
    customers = (
        Customer.objects.filter(plan_id=plan.pk)
        .select_related("organization", "router", "plan")
        .iterator()
    )
    for customer in customers:
        try:
            result = sync_customer_subscription_access(
                customer, provision=True, reauthenticate=True
            )
            if isinstance(result, dict) and result.get("ok"):
                updated += 1
        except Exception:
            continue
    return updated


def _get_posted_package(request, org):
    package_id = (request.POST.get("package_id") or "").strip()
    if not org or not package_id.isdigit():
        return None
    return BillingPlan.objects.filter(pk=int(package_id), organization=org).first()


def _handle_suspend_package(request, org, *, success_url_name: str):
    """Suspend or unsuspend a package. Returns response_or_none."""
    if request.method != "POST":
        return None

    action = (request.POST.get("action") or "").strip()
    if action not in {"suspend_package", "unsuspend_package"}:
        return None

    if not org:
        messages.error(request, "No organization is linked to this workspace.")
        return redirect(success_url_name)

    plan = _get_posted_package(request, org)
    if not plan:
        messages.error(request, "Choose a package to update.")
        return redirect(success_url_name)

    if action == "suspend_package":
        if not plan.is_active:
            messages.info(request, f"Package “{plan.name}” is already suspended.")
            return redirect(success_url_name)
        plan.is_active = False
        plan.save(update_fields=["is_active"])
        messages.success(
            request,
            f"Package “{plan.name}” suspended. It won’t be offered to new assignments.",
        )
        return redirect(success_url_name)

    if plan.is_active:
        messages.info(request, f"Package “{plan.name}” is already active.")
        return redirect(success_url_name)
    plan.is_active = True
    plan.save(update_fields=["is_active"])
    messages.success(request, f"Package “{plan.name}” unsuspended and available again.")
    return redirect(success_url_name)


def _handle_delete_package(request, org, *, success_url_name: str):
    """Permanently delete a package. Returns response_or_none."""
    if request.method != "POST":
        return None

    action = (request.POST.get("action") or "").strip()
    if action != "delete_package":
        return None

    if not org:
        messages.error(request, "No organization is linked to this workspace.")
        return redirect(success_url_name)

    plan = _get_posted_package(request, org)
    if not plan:
        messages.error(request, "Choose a package to delete.")
        return redirect(success_url_name)

    if plan.stk_push_requests.exists():
        messages.error(
            request,
            f"Cannot delete “{plan.name}” because payment history references it. Suspend it instead.",
        )
        return redirect(success_url_name)

    customer_count = plan.customers.count()
    name = plan.name
    plan.delete()
    if customer_count:
        messages.success(
            request,
            f"Package “{name}” deleted. {customer_count} linked client(s) were kept and unassigned from it.",
        )
    else:
        messages.success(request, f"Package “{name}” deleted.")
    return redirect(success_url_name)


def _lead_payment_rows(org):
    """Successful lead-allocation STK rows for an ISP, including reversals."""
    rows = []
    if not org:
        return rows
    for stk in (
        StkPushRequest.objects.filter(
            organization=org,
            purpose=StkPushRequest.Purpose.LEAD_ALLOCATION,
            status=StkPushRequest.Status.SUCCESS,
        )
        .select_related("customer", "invoice", "payment")
        .order_by("-completed_at", "-pk")[:40]
    ):
        raw = stk.raw_callback if isinstance(stk.raw_callback, dict) else {}
        notes = (stk.invoice.notes if stk.invoice_id else "") or ""
        reversed_payment = bool(raw.get("lead_allocation_reversed")) or (
            "[LEAD ALLOCATION REVERSED]" in notes
        )
        rows.append(
            {
                "stk": stk,
                "customer": stk.customer,
                "invoice": stk.invoice,
                "payment": stk.payment,
                "reversed": reversed_payment,
                "reversal_reason": (raw.get("reversal_reason") or "").strip(),
                "amount": stk.amount,
                "completed_at": stk.completed_at,
                "receipt": stk.mpesa_receipt
                or (stk.payment.reference if stk.payment_id else "")
                or "",
            }
        )
    return rows


@login_required
def dashboard(request):
    """Billing module dashboard."""
    blocked = _require_client_workspace(request)
    if blocked:
        return blocked

    org = resolve_organization(request.user, request)

    if org:
        customer_stats = Customer.objects.filter(organization=org).aggregate(
            customers=Count("id"),
            active_customers=Count("id", filter=Q(status="active")),
        )
        invoice_stats = Invoice.objects.filter(organization=org).aggregate(
            pending_invoices=Count("id", filter=Q(status="pending")),
        )
        revenue = (
            Payment.objects.filter(organization=org).aggregate(total=Sum("amount"))["total"]
            or 0
        )
        payment_count = Payment.objects.filter(organization=org).count()
        stats = {
            "customers": customer_stats["customers"] or 0,
            "active_customers": customer_stats["active_customers"] or 0,
            "pending_invoices": invoice_stats["pending_invoices"] or 0,
            "revenue": revenue,
            "payment_count": payment_count,
        }
        payments = list(
            Payment.objects.filter(organization=org)
            .select_related("invoice", "invoice__customer")
            .order_by("-received_at")
        )
        attention_customers = customers_needing_renewal_attention(org)
        stats["attention_customers"] = len(attention_customers)
    else:
        stats = {
            "customers": 0,
            "active_customers": 0,
            "pending_invoices": 0,
            "revenue": 0,
            "payment_count": 0,
            "attention_customers": 0,
        }
        payments = []
        attention_customers = []

    return render(
        request,
        "billing/dashboard.html",
        client_page_context(
            request,
            active_nav="billing",
            sidebar_active="billing",
            page_title="Billings",
            stats=stats,
            payments=payments,
            attention_customers=attention_customers,
        ),
    )


@login_required
def lead_payments(request):
    """Lead allocation payments and reversals for the active ISP."""
    blocked = _require_client_workspace(request)
    if blocked:
        return blocked

    org = resolve_organization(request.user, request)
    rows = _lead_payment_rows(org)
    return render(
        request,
        "billing/lead_payments.html",
        client_page_context(
            request,
            active_nav="billing",
            sidebar_active="leads_billing",
            page_title="Lead payments",
            page_kicker="Billings",
            page_subtitle="Sales ticket allocation fees paid by your ISP, including reversals.",
            lead_payments=rows,
            lead_payment_count=len(rows),
            lead_reversal_count=sum(1 for row in rows if row["reversed"]),
        ),
    )


@login_required
@require_POST
def subscription_stk_pay(request, customer_id: int):
    """Initiate M-Pesa STK Push for a client's package renewal."""
    blocked = _require_client_workspace(request)
    if blocked:
        return JsonResponse({"ok": False, "error": "Not allowed."}, status=403)

    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization linked."}, status=400)

    customer = get_object_or_404(
        Customer.objects.select_related("plan", "organization"),
        pk=customer_id,
        organization=org,
    )
    phone = (request.POST.get("phone") or "").strip()
    result = start_subscription_stk_payment(
        organization=org,
        customer=customer,
        phone=phone,
        user=request.user,
        request=request,
    )
    status = 200 if result.get("ok") else 400
    return JsonResponse(result, status=status)


@login_required
@require_GET
def subscription_stk_status(request, stk_id: int):
    """Poll STK Push status (also queries Daraja when callback cannot reach localhost)."""
    blocked = _require_client_workspace(request)
    if blocked:
        return JsonResponse({"ok": False, "error": "Not allowed."}, status=403)

    org = resolve_organization(request.user, request)
    if not org:
        return JsonResponse({"ok": False, "error": "No organization linked."}, status=400)

    stk = get_object_or_404(
        StkPushRequest.objects.select_related("customer", "organization"),
        pk=stk_id,
        organization=org,
    )
    return JsonResponse(refresh_stk_status(stk))


@login_required
def packages(request):
    """List, register, edit, suspend, and delete billing packages."""
    blocked = _require_client_workspace(request)
    if blocked:
        return blocked

    org = resolve_organization(request.user, request)
    package_form, open_modal, early = _handle_register_package(
        request, org, success_url_name="billing:packages"
    )
    if early:
        return early

    edit_form, edit_modal, early = _handle_edit_package(
        request, org, success_url_name="billing:packages"
    )
    if early:
        return early
    if edit_modal:
        open_modal = edit_modal

    early = _handle_suspend_package(request, org, success_url_name="billing:packages")
    if early:
        return early

    early = _handle_delete_package(request, org, success_url_name="billing:packages")
    if early:
        return early

    package_list = list(
        BillingPlan.objects.filter(organization=org)
        .annotate(
            customer_count=Count("customers"),
            stk_count=Count("stk_push_requests"),
        )
        .prefetch_related("routers")
        .order_by("service_type", "price", "name")
        if org
        else BillingPlan.objects.none()
    )
    pppoe_packages = [
        p for p in package_list if p.service_type == BillingPlan.ServiceType.PPPOE
    ]
    hotspot_packages = [
        p for p in package_list if p.service_type == BillingPlan.ServiceType.HOTSPOT
    ]

    return render(
        request,
        "billing/packages.html",
        client_page_context(
            request,
            active_nav="billing",
            sidebar_active="packages",
            page_title="Packages",
            page_kicker="Billing",
            page_subtitle="Manage internet packages for this organization.",
            packages=package_list,
            pppoe_packages=pppoe_packages,
            hotspot_packages=hotspot_packages,
            package_count=len(package_list),
            pppoe_package_count=len(pppoe_packages),
            hotspot_package_count=len(hotspot_packages),
            package_form=package_form,
            package_edit_form=edit_form,
            open_billing_modal=open_modal,
        ),
    )


def _renew_page_context(customer):
    from django.utils import timezone

    from billing.services import (
        customer_receives_internet,
        customer_subscription_expired,
        subscription_period_allows,
    )

    today = timezone.localdate()
    allowed = customer_receives_internet(customer, today=today)
    expired = customer_subscription_expired(customer, today=today)
    start = customer.package_start
    if start is not None:
        start_day = timezone.localtime(start).date() if hasattr(start, "hour") else start
        not_started = today < start_day
    else:
        not_started = False
    org = getattr(customer, "organization", None)
    return {
        "customer": customer,
        "organization": org,
        "org_name": getattr(org, "name", "") or "ISPCENTRIC",
        "allowed": allowed,
        "expired": expired,
        "not_started": not_started,
        "period_ok": subscription_period_allows(customer, today=today),
        "today": today,
        "plan": customer.plan,
        "popup": True,
    }


def subscription_renew(request, token: str):
    """Public renew notice shown when a subscriber's package period has ended."""
    from billing.services import resolve_customer_from_renew_token

    customer = resolve_customer_from_renew_token(token)
    if customer is None:
        return render(
            request,
            "billing/subscription_renew.html",
            {
                "invalid": True,
                "org_name": "ISPCENTRIC",
                "popup": True,
            },
            status=404,
        )
    return render(
        request,
        "billing/subscription_renew.html",
        _renew_page_context(customer),
    )


def subscription_renew_hotspot(request, token: str):
    """
    Bare HTML login page fetched onto client CPE Hotspot folders.

    Phones show this as the captive-portal popup when Wi‑Fi connects after expiry.
    """
    from billing.services import resolve_customer_from_renew_token

    customer = resolve_customer_from_renew_token(token)
    if customer is None:
        return render(
            request,
            "billing/subscription_renew_hotspot.html",
            {
                "invalid": True,
                "org_name": "ISPCENTRIC",
                "customer_name": "Subscriber",
            },
            content_type="text/html; charset=utf-8",
            status=404,
        )
    ctx = _renew_page_context(customer)
    org = ctx.get("organization")
    return render(
        request,
        "billing/subscription_renew_hotspot.html",
        {
            "invalid": False,
            "org_name": ctx["org_name"],
            "organization": org,
            "customer": customer,
            "customer_name": customer.full_name,
            "account_number": customer.account_number,
            "package_end": customer.package_end,
            "plan_name": customer.plan.name if customer.plan_id else "",
            "plan": customer.plan,
            "expired": ctx["expired"],
            "not_started": ctx["not_started"],
            "allowed": ctx["allowed"],
        },
        content_type="text/html; charset=utf-8",
    )
