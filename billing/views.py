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


@login_required
def dashboard(request):
    """Billing module dashboard."""
    blocked = _require_client_workspace(request)
    if blocked:
        return blocked

    org = resolve_organization(request.user, request)
    package_form, open_modal, early = _handle_register_package(
        request, org, success_url_name="billing:dashboard"
    )
    if early:
        return early

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
        stats = {
            "customers": customer_stats["customers"] or 0,
            "active_customers": customer_stats["active_customers"] or 0,
            "pending_invoices": invoice_stats["pending_invoices"] or 0,
            "revenue": revenue,
            "packages": BillingPlan.objects.filter(organization=org).count(),
        }
        recent_invoices = (
            Invoice.objects.filter(organization=org)
            .select_related("customer")
            .order_by("-issued_at")[:8]
        )
        packages = (
            BillingPlan.objects.filter(organization=org)
            .order_by("price", "name")[:6]
        )
        attention_customers = customers_needing_renewal_attention(org)
        stats["attention_customers"] = len(attention_customers)
    else:
        stats = {
            "customers": 0,
            "active_customers": 0,
            "pending_invoices": 0,
            "revenue": 0,
            "packages": 0,
            "attention_customers": 0,
        }
        recent_invoices = Invoice.objects.none()
        packages = BillingPlan.objects.none()
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
            recent_invoices=recent_invoices,
            attention_customers=attention_customers,
            packages=packages,
            package_form=package_form,
            open_billing_modal=open_modal,
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
    """List and register billing packages for the active organization."""
    blocked = _require_client_workspace(request)
    if blocked:
        return blocked

    org = resolve_organization(request.user, request)
    package_form, open_modal, early = _handle_register_package(
        request, org, success_url_name="billing:packages"
    )
    if early:
        return early

    package_list = list(
        BillingPlan.objects.filter(organization=org).order_by("price", "name")
        if org
        else BillingPlan.objects.none()
    )

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
            package_count=len(package_list),
            package_form=package_form,
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
