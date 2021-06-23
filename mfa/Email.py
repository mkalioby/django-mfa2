import datetime
import random
from random import randint

from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.template.context_processors import csrf
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache

from .Common import send
from .models import UserKey
from .views import login


def send_email(request, username, secret):
    """Send Email to the user after rendering `mfa_email_token_template`"""
    User = get_user_model()
    key = getattr(User, "USERNAME_FIELD", "username")
    kwargs = {key: username}
    user = User.objects.get(**kwargs)
    res = render(
        request,
        "mfa_email_token_template.html",
        {"request": request, "user": user, "otp": secret},
    )
    return send([user.email], "OTP", res.content.decode())


@never_cache
def start(request):
    """Start adding email as a 2nd factor"""
    context = csrf(request)
    if request.method == "POST":
        if request.session["email_secret"] == request.POST["otp"]:  # if successful
            uk = UserKey()
            uk.username = request.user.username
            uk.key_type = "Email"
            uk.enabled = 1
            uk.save()
            return HttpResponseRedirect(
                reverse(
                    getattr(settings, "MFA_REDIRECT_AFTER_REGISTRATION", "mfa_home")
                )
            )
        context["invalid"] = True
    else:
        request.session["email_secret"] = str(
            randint(0, 100000)
        )  # generate a random integer
        if send_email(request, request.user.username, request.session["email_secret"]):
            context["sent"] = True
    return render(request, "Email/Add.html", context)


@never_cache
def auth(request):
    """Authenticating the user by email."""
    context = csrf(request)
    if request.method == "POST":
        if request.session["email_secret"] == request.POST["otp"].strip():
            uk = UserKey.objects.get(
                username=request.session["base_username"], key_type="Email"
            )
            mfa = {"verified": True, "method": "Email", "id": uk.id}
            if getattr(settings, "MFA_RECHECK", False):
                mfa["next_check"] = datetime.datetime.timestamp(
                    datetime.datetime.now()
                    + datetime.timedelta(
                        seconds=random.randint(
                            settings.MFA_RECHECK_MIN, settings.MFA_RECHECK_MAX
                        )
                    )
                )
            request.session["mfa"] = mfa

            uk.last_used = timezone.now()
            uk.save()
            return login(request)
        context["invalid"] = True
    else:
        request.session["email_secret"] = str(randint(0, 100000))
        if send_email(
            request, request.session["base_username"], request.session["email_secret"]
        ):
            context["sent"] = True
    return render(request, "Email/Auth.html", context)
