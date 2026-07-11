from django.contrib.auth.decorators import login_required
from django.db.models import Sum
from django.shortcuts import redirect, render

from accounts.routing import home_url_for_user
from core.views import resolve_organization
from .models import Customer, Invoice, Payment


@login_required
def dashboard(request):
    """Billing module dashboard."""
    employee = getattr(request.user, "employee_profile", None)
    if employee is not None:
        return redirect(home_url_for_user(request.user))

    org = resolve_organization(request.user)
    customers = Customer.objects.filter(organization=org) if org else Customer.objects.none()
    invoices = Invoice.objects.filter(organization=org) if org else Invoice.objects.none()
    payments = Payment.objects.filter(organization=org) if org else Payment.objects.none()

    stats = {
        "customers": customers.count(),
        "active_customers": customers.filter(status="active").count(),
        "pending_invoices": invoices.filter(status="pending").count(),
        "revenue": payments.aggregate(total=Sum("amount"))["total"] or 0,
    }

    return render(
        request,
        "billing/dashboard.html",
        {
            "organization": org,
            "is_owner": bool(org and org.owner_id == request.user.id),
            "stats": stats,
            "recent_invoices": invoices.select_related("customer")[:8],
            "recent_customers": customers.select_related("plan")[:8],
            "active_nav": "billing",
        },
    )
