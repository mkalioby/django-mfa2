from django.contrib.auth.decorators import login_required
from django.shortcuts import render


@login_required()
def home(request):
    return render(request, "home.html", {})


@login_required()
def registered(request):
    return render(request, "home.html", {"registered": True})
