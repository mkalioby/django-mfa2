from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse

from mfa.helpers import has_mfa


def loginView(request):
    context = {}
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(username=username, password=password)
        if user:
            res = has_mfa(
                username=username, request=request
            )  # has_mfa returns false or HttpResponseRedirect
            if res:
                return res
            return create_session(request, user.username)
        context["invalid"] = True
    return render(request, "login.html", context)


def create_session(request, username):
    user = User.objects.get(username=username)
    user.backend = "django.contrib.auth.backends.ModelBackend"
    login(request, user)
    return HttpResponseRedirect(reverse("home"))


def logoutView(request):
    logout(request)
    return render(request, "logout.html", {})
