from django.contrib import admin

from .models import BillingPlan, Customer, CustomerDevice, Invoice, Payment


@admin.register(BillingPlan)
class BillingPlanAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "organization",
        "download_speed_mbps",
        "upload_speed_mbps",
        "speed_mbps",
        "max_devices",
        "price",
        "duration",
        "is_active",
    )
    list_filter = ("duration", "service_type", "is_active")
    search_fields = ("name", "organization__name")
    readonly_fields = ("created_at", "speed_mbps")
    fields = (
        "organization",
        "name",
        "description",
        "image",
        "price",
        "download_speed_mbps",
        "upload_speed_mbps",
        "speed_mbps",
        "duration",
        "max_devices",
        "service_type",
        "routers",
        "is_active",
        "created_at",
    )
    filter_horizontal = ("routers",)


class CustomerDeviceInline(admin.TabularInline):
    model = CustomerDevice
    extra = 0
    fields = ("mac", "created_at", "last_seen_at")
    readonly_fields = ("created_at", "last_seen_at")


@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = (
        "full_name",
        "sales_ticket_number",
        "account_number",
        "service_type",
        "pppoe_username",
        "router",
        "phone",
        "status",
        "plan",
        "organization",
    )
    list_filter = ("status", "service_type")
    search_fields = (
        "full_name",
        "sales_ticket_number",
        "account_number",
        "phone",
        "pppoe_username",
    )
    autocomplete_fields = ("plan",)
    raw_id_fields = ("router", "organization")
    inlines = (CustomerDeviceInline,)


@admin.register(CustomerDevice)
class CustomerDeviceAdmin(admin.ModelAdmin):
    list_display = ("mac", "customer", "organization", "created_at", "last_seen_at")
    search_fields = ("mac", "customer__full_name", "customer__account_number")
    raw_id_fields = ("customer", "organization")


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
