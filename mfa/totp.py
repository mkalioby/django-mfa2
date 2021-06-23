import datetime
import random
import time

import pyotp
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.template.context_processors import csrf
from django.utils import timezone
from django.views.decorators.cache import never_cache

from .Common import get_redirect_url
from .models import UserKey, OTPTracker
from .views import login


def verify_login(request, username, token):
    for key in UserKey.objects.filter(username=username, key_type="TOTP"):
        totp = pyotp.TOTP(key.properties["secret_key"])
        if totp.verify(token, valid_window=30):
            if OTPTracker.objects.filter(username=username, value=token).exists():
                return [False, "Used Before, please generate another token"]
            TOTP_Tracker.objects.create(username=username,value=token, success=True)
            key.last_used = timezone.now()
            key.save()
            return [True, key.id]
    TOTP_Tracker.objects.create(username = username, value = token, success = False)
    return [False,"Invalid Token"]


def recheck(request):
    context = csrf(request)
    context["mode"] = "recheck"
    if request.method == "POST":
        if verify_login(request, request.user.username, token=request.POST["otp"]):
            request.session["mfa"]["rechecked_at"] = time.time()
            return JsonResponse({"recheck": True})
        else:
            return JsonResponse({"recheck": False})
    return render(request, "TOTP/recheck.html", context)


@never_cache
def auth(request):
    context = csrf(request)
    if request.method == "POST":
        res = verify_login(
            request, request.session["base_username"], token=request.POST["otp"]
        )
        if res[0]:
            mfa = {"verified": True, "method": "TOTP", "id": res[1]}
            if getattr(settings, "MFA_RECHECK", False):
                mfa["next_check"] = datetime.datetime.timestamp(
                    (
                        datetime.datetime.now()
                        + datetime.timedelta(
                            seconds=random.randint(
                                settings.MFA_RECHECK_MIN, settings.MFA_RECHECK_MAX
                            )
                        )
                    )
                )
            request.session["mfa"] = mfa
            return login(request)
        context["invalid"] = True
        context["invalid_msg"] = res[1]
    return render(request, "TOTP/Auth.html", context)


def getToken(request):
    secret_key = pyotp.random_base32()
    totp = pyotp.TOTP(secret_key)
    request.session["new_mfa_answer"] = totp.now()
    return JsonResponse(
        {
            "qr": pyotp.totp.TOTP(secret_key).provisioning_uri(
                str(request.user.username), issuer_name=settings.TOKEN_ISSUER_NAME
            ),
            "secret_key": secret_key,
        }
    )


def verify(request):
    answer = request.GET["answer"]
    secret_key = request.GET["key"]
    totp = pyotp.TOTP(secret_key)
    if totp.verify(answer, valid_window=60):
        uk = UserKey()
        uk.username = request.user.username
        uk.properties = {"secret_key": secret_key}
        uk.key_type = "TOTP"
        uk.save()
        return HttpResponse("Success")
    else:
        return HttpResponse("Error")


@never_cache
def start(request):
    """Start Adding Time One Time Password (TOTP)"""
    return render(request, "TOTP/Add.html", get_redirect_url())
