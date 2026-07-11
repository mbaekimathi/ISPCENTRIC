from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q, Sum
from django.shortcuts import redirect, render

from accounts.routing import home_url_for_user, is_viewing_as_client
from core.views import client_page_context, resolve_organization

from .forms import BillingPackageRegisterForm
from .models import BillingPlan, Customer, Invoice, Payment


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
        recent_customers = (
            Customer.objects.filter(organization=org)
            .select_related("plan")
            .order_by("-created_at")[:8]
        )
        packages = (
            BillingPlan.objects.filter(organization=org)
            .order_by("price", "name")[:6]
        )
    else:
        stats = {
            "customers": 0,
            "active_customers": 0,
            "pending_invoices": 0,
            "revenue": 0,
            "packages": 0,
        }
        recent_invoices = Invoice.objects.none()
        recent_customers = Customer.objects.none()
        packages = BillingPlan.objects.none()

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
            recent_customers=recent_customers,
            packages=packages,
            package_form=package_form,
            open_billing_modal=open_modal,
        ),
    )


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

    package_list = (
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
            package_count=package_list.count() if hasattr(package_list, "count") else len(package_list),
            package_form=package_form,
            open_billing_modal=open_modal,
        ),
    )
