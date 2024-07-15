import datetime
from random import randint
from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.template.context_processors import csrf
from django.contrib.auth import get_user_model
from django.http import HttpResponseRedirect
from django.conf import settings

from .models import User_Keys

from .views import login
from .Common import send, get_username_field, set_next_recheck


def sendEmail(request, username, secret):
    """Send Email to the user after rendering `mfa_email_token_template`"""
    User, UsernameField = get_username_field()
    kwargs = {UsernameField: username}
    user = User.objects.get(**kwargs)
    res = render(
        request,
        "mfa_email_token_template.html",
        {"request": request, "user": user, "otp": secret},
    )
    subject = getattr(settings, "MFA_OTP_EMAIL_SUBJECT", "OTP")
    if getattr(settings, "MFA_SHOW_OTP_IN_EMAIL_SUBJECT", False):
        if "%s" in subject:
            subject = subject % secret
        else:
            subject = secret + " " + subject
    return send([user.email], subject, res.content.decode())


@never_cache
def start(request):
    """Start adding email as a 2nd factor"""
    context = csrf(request)
    if request.method == "POST":
        if request.session["email_secret"] == request.POST["otp"]:  # if successful
            uk = User_Keys()
            User, USERNAME_FIELD = get_username_field()
            uk.username = USERNAME_FIELD
            uk.key_type = "Email"
            uk.enabled = 1
            uk.save()

            try:
                from django.core.urlresolvers import reverse  # pyre-ignore[21]
            except:
                from django.urls import reverse
            if (
                getattr(settings, "MFA_ENFORCE_RECOVERY_METHOD", False)
                and not User_Keys.objects.filter(
                    key_type="RECOVERY", username=request.user.username
                ).exists()
            ):
                request.session["mfa_reg"] = {
                    "method": "Email",
                    "name": getattr(settings, "MFA_RENAME_METHODS", {}).get(
                        "Email", "Email"
                    ),
                }
            else:
                return HttpResponseRedirect(
                    reverse(
                        getattr(settings, "MFA_REDIRECT_AFTER_REGISTRATION", "mfa_home")
                    )
                )
        context["invalid"] = True
    else:
        request.session["email_secret"] = str(randint(0, 1000000)).zfill(
            6
        )  # generate a random integer

        if sendEmail(request, request.user.username, request.session["email_secret"]):
            context["sent"] = True
    return render(request, "Email/Add.html", context)


@never_cache
def auth(request):
    """Authenticating the user by email."""
    context = csrf(request)
    if request.method == "POST":
        username = request.session["base_username"]

        if request.session["email_secret"] == request.POST["otp"].strip():
            email_keys = User_Keys.objects.filter(username=username, key_type="Email")
            if email_keys.exists():
                uk = email_keys.first()
            elif getattr(settings, "MFA_ENFORCE_EMAIL_TOKEN", False):
                uk = User_Keys()
                uk.username = username
                uk.key_type = "Email"
                uk.enabled = 1
                uk.save()
            else:
                raise Exception("Email is not a valid method for this user")

            mfa = {"verified": True, "method": "Email", "id": uk.id}
            mfa.update(set_next_recheck())
            request.session["mfa"] = mfa

            from django.utils import timezone

            uk.last_used = timezone.now()
            uk.save()
            return login(request)
        context["invalid"] = True
    else:
        request.session["email_secret"] = str(randint(0, 1000000)).zfill(6)
        if sendEmail(
            request, request.session["base_username"], request.session["email_secret"]
        ):
            context["sent"] = True
    return render(request, "Email/Auth.html", context)
