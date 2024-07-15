import random
import datetime
import time

import pyotp
from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.http import HttpResponse, JsonResponse
from django.template.context_processors import csrf
from django.conf import settings
from django.utils import timezone
from .views import login
from .Common import get_redirect_url, set_next_recheck
from .models import User_Keys


def verify_login(request, username, token):
    for key in User_Keys.objects.filter(username=username, key_type="TOTP"):
        totp = pyotp.TOTP(key.properties["secret_key"])
        if totp.verify(token, valid_window=30):
            key.last_used = timezone.now()
            key.save()
            return [True, key.id]
    return [False]


def recheck(request):
    context = csrf(request)
    context["mode"] = "recheck"
    if request.method == "POST":
        if verify_login(request, request.user.username, token=request.POST["otp"])[0]:
            mfa = request.session["mfa"]
            mfa["rechecked_at"] = time.time()
            mfa.update(set_next_recheck())
            return JsonResponse({"recheck": True})
        else:
            return JsonResponse({"recheck": False})
    return render(request, "TOTP/recheck.html", context)


@never_cache
def auth(request):
    context = csrf(request)
    if request.method == "POST":
        tokenLength = len(request.POST["otp"])
        if tokenLength == 6:
            # TOTO code check
            res = verify_login(
                request, request.session["base_username"], token=request.POST["otp"]
            )
            if res[0]:
                mfa = {"verified": True, "method": "TOTP", "id": res[1]}
                mfa.update(set_next_recheck())
                request.session["mfa"] = mfa
                return login(request)
        context["invalid"] = True
    return render(request, "TOTP/Auth.html", context)


def getToken(request):
    secret_key = pyotp.random_base32()
    totp = pyotp.TOTP(secret_key)
    request.session["new_mfa_answer"] = totp.now()
    qr = pyotp.totp.TOTP(secret_key).provisioning_uri(
        str(request.user.username), issuer_name=settings.TOKEN_ISSUER_NAME
    )
    return JsonResponse(
        {
            "qr": qr,
            "secret_key": secret_key,
        }
    )


def verify(request):
    answer = request.GET["answer"]
    secret_key = request.GET["key"]
    totp = pyotp.TOTP(secret_key)
    if totp.verify(answer, valid_window=60):
        uk = User_Keys()
        uk.username = request.user.username
        uk.properties = {"secret_key": secret_key}
        # uk.name="Authenticatior #%s"%User_Keys.objects.filter(username=user.username,type="TOTP")
        uk.key_type = "TOTP"
        uk.save()
        if (
            getattr(settings, "MFA_ENFORCE_RECOVERY_METHOD", False)
            and not User_Keys.objects.filter(
                key_type="RECOVERY", username=request.user.username
            ).exists()
        ):
            request.session["mfa_reg"] = {
                "method": "TOTP",
                "name": getattr(settings, "MFA_RENAME_METHODS", {}).get("TOTP", "TOTP"),
            }
            return HttpResponse("RECOVERY")
        else:
            return HttpResponse("Success")
    else:
        return HttpResponse("Error")


@never_cache
def start(request):
    """Start Adding Time One Time Password (TOTP)"""
    context = get_redirect_url()
    context["RECOVERY_METHOD"] = getattr(settings, "MFA_RENAME_METHODS", {}).get(
        "RECOVERY", "Recovery codes"
    )
    context["method"] = {
        "name": getattr(settings, "MFA_RENAME_METHODS", {}).get("TOTP", "Authenticator")
    }
    return render(request, "TOTP/Add.html", context)
