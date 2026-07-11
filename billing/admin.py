from django.contrib import admin

from .models import BillingPlan, Customer, Invoice, Payment


@admin.register(BillingPlan)
class BillingPlanAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "price", "speed_mbps", "duration", "is_active")
    list_filter = ("duration", "is_active")
    search_fields = ("name", "organization__name")


@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = ("full_name", "account_number", "phone", "status", "plan", "organization")
    list_filter = ("status",)
    search_fields = ("full_name", "account_number", "phone")


@admin.register(Invoice)
class InvoiceAdmin(admin.ModelAdmin):
    list_display = ("invoice_number", "customer", "amount", "status", "due_date")
    list_filter = ("status",)
    search_fields = ("invoice_number", "customer__full_name")


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ("reference", "invoice", "amount", "method", "received_at")
    list_filter = ("method",)
    search_fields = ("reference", "invoice__invoice_number")
