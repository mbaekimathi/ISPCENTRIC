from django.contrib.auth.decorators import login_required
from django.db.models import Sum
from django.shortcuts import redirect, render
from django.views import View

from accounts.models import Employee, Organization
from accounts.routing import home_url_for_user
from billing.models import Customer, Invoice, Payment


def resolve_organization(user):
    org = Organization.objects.filter(owner=user).first()
    if org:
        return org
    profile = getattr(user, "employee_profile", None)
    if profile:
        return profile.organization
    return None


class LandingView(View):
    template_name = "core/landing.html"

    def get(self, request):
        if request.user.is_authenticated:
            return redirect(home_url_for_user(request.user))
        return render(request, self.template_name)


@login_required
def workspace(request):
    """Main ISPCENTRIC workspace home — modules hub (not billing-only)."""
    employee = getattr(request.user, "employee_profile", None)
    if employee is not None:
        return redirect(home_url_for_user(request.user))

    org = resolve_organization(request.user)
    is_owner = bool(org and org.owner_id == request.user.id)

    company_employees = (
        Employee.objects.filter(organization=org).select_related("user").order_by("-created_at")
        if org and is_owner
        else Employee.objects.none()
    )
    unassigned_pending = (
        Employee.objects.filter(
            organization__isnull=True,
            status=Employee.Status.PENDING_APPROVAL,
        )
        .select_related("user")
        .order_by("-created_at")
        if is_owner
        else Employee.objects.none()
    )

    customers = Customer.objects.filter(organization=org) if org else Customer.objects.none()
    invoices = Invoice.objects.filter(organization=org) if org else Invoice.objects.none()
    payments = Payment.objects.filter(organization=org) if org else Payment.objects.none()

    modules = [
        {
            "name": "Billing",
            "description": "Plans, customers, invoices, and payments.",
            "url_name": "billing:dashboard",
            "status": "active",
        },
        {
            "name": "Staff",
            "description": "Employee approvals, roles, and access.",
            "url_name": "core:workspace",
            "anchor": "staff",
            "status": "active",
        },
        {
            "name": "Network",
            "description": "Routers, monitoring, and connectivity.",
            "url_name": None,
            "status": "coming",
        },
        {
            "name": "Hotspot",
            "description": "Portals, vouchers, and guest access.",
            "url_name": None,
            "status": "coming",
        },
    ]

    return render(
        request,
        "core/workspace.html",
        {
            "organization": org,
            "is_owner": is_owner,
            "modules": modules,
            "company_employees": company_employees,
            "unassigned_pending": unassigned_pending,
            "stats": {
                "employees": company_employees.count(),
                "pending_staff": unassigned_pending.count()
                + company_employees.filter(status=Employee.Status.PENDING_APPROVAL).count(),
                "customers": customers.count(),
                "revenue": payments.aggregate(total=Sum("amount"))["total"] or 0,
                "pending_invoices": invoices.filter(status="pending").count(),
            },
            "active_nav": "workspace",
        },
    )
