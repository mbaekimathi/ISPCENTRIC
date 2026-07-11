from django.shortcuts import redirect, render
from django.views import View

from accounts.routing import home_url_for_user


class LandingView(View):
    template_name = "core/landing.html"

    def get(self, request):
        if request.user.is_authenticated:
            return redirect(home_url_for_user(request.user, request))
        return render(request, self.template_name)
