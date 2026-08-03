from django.shortcuts import redirect, render
from django.urls import reverse
from django.views import View

from accounts.models import ClientSettings
from accounts.routing import home_url_for_user


class LandingView(View):
    template_name = "core/landing.html"

    def get(self, request):
        if request.user.is_authenticated:
            return redirect(home_url_for_user(request.user, request))
        # Referral links that land on `/` still open register with the code filled.
        ref = (request.GET.get("ref") or "").strip()
        if ref and ClientSettings.get_solo().referral_enabled:
            register_url = reverse("accounts:register")
            return redirect(f"{register_url}?ref={ref}")
        client_settings = ClientSettings.get_solo()
        return render(
            request,
            self.template_name,
            {
                "landing_register_enabled": bool(
                    client_settings.landing_register_enabled
                ),
            },
        )
