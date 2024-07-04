import json

from u2flib_server.u2f import (
    begin_registration,
    begin_authentication,
    complete_registration,
    complete_authentication,
)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from django.shortcuts import render


from django.template.context_processors import csrf
from django.http import HttpResponse, JsonResponse
from django.conf import settings
from .models import User_Keys
from .views import login
from .Common import get_redirect_url
from django.utils import timezone


def recheck(request):
    context = csrf(request)
    context["mode"] = "recheck"
    s = sign(request.user.username)
    request.session["_u2f_challenge_"] = s[0]
    context["token"] = s[1]
    request.session["mfa_recheck"] = True
    return render(request, "U2F/recheck.html", context)


def process_recheck(request):
    x = validate(request, request.user.username)
    if x is True:
        import time

        request.session["mfa"]["rechecked_at"] = time.time()
        return JsonResponse({"recheck": True})
    return x


def check_errors(request, data):
    if "errorCode" in data:
        if data["errorCode"] == 0:
            return True
        if data["errorCode"] == 4:
            return HttpResponse("Invalid Security Key")
        if data["errorCode"] == 1:
            return auth(request)
    return True


def validate(request, username):
    import datetime, random

    data = json.loads(request.POST["response"])

    res = check_errors(request, data)
    if res != True:
        return res

    challenge = request.session.pop("_u2f_challenge_")
    device, c, t = complete_authentication(challenge, data, [settings.U2F_APPID])
    try:
        key = User_Keys.objects.get(
            username=username,
            properties__icontains='"publicKey": "%s"' % device["publicKey"],
        )
        key.last_used = timezone.now()
        key.save()
        mfa = {"verified": True, "method": "U2F", "id": key.id}
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
        return True
    except:
        return False


def auth(request):
    context = csrf(request)
    s = sign(request.session["base_username"])
    request.session["_u2f_challenge_"] = s[0]
    context["token"] = s[1]
    context["method"] = {
        "name": getattr(settings, "MFA_RENAME_METHODS", {}).get(
            "U2F", "Classical Security Key"
        )
    }
    return render(request, "U2F/Auth.html", context)


def start(request):
    enroll = begin_registration(settings.U2F_APPID, [])
    request.session["_u2f_enroll_"] = enroll.json
    context = csrf(request)
    context["token"] = json.dumps(enroll.data_for_client)
    context.update(get_redirect_url())
    context["method"] = {
        "name": getattr(settings, "MFA_RENAME_METHODS", {}).get(
            "U2F", "Classical Security Key"
        )
    }
    context["RECOVERY_METHOD"] = getattr(settings, "MFA_RENAME_METHODS", {}).get(
        "RECOVERY", "Recovery codes"
    )
    return render(request, "U2F/Add.html", context)


def bind(request):
    import hashlib

    enroll = request.session["_u2f_enroll_"]
    data = json.loads(request.POST["response"])
    device, cert = complete_registration(enroll, data, [settings.U2F_APPID])
    cert = x509.load_der_x509_certificate(cert, default_backend())
    cert_hash = hashlib.md5(cert.public_bytes(Encoding.PEM)).hexdigest()
    q = User_Keys.objects.filter(key_type="U2F", properties__icontains=cert_hash)
    if q.exists():
        return HttpResponse(
            "This key is registered before, it can't be registered again."
        )
    User_Keys.objects.filter(username=request.user.username, key_type="U2F").delete()
    uk = User_Keys()
    uk.username = request.user.username
    uk.owned_by_enterprise = getattr(settings, "MFA_OWNED_BY_ENTERPRISE", False)
    uk.properties = {"device": json.loads(device.json), "cert": cert_hash}
    uk.key_type = "U2F"
    uk.save()
    if (
        getattr(settings, "MFA_ENFORCE_RECOVERY_METHOD", False)
        and not User_Keys.objects.filter(
            key_type="RECOVERY", username=request.user.username
        ).exists()
    ):
        request.session["mfa_reg"] = {
            "method": "U2F",
            "name": getattr(settings, "MFA_RENAME_METHODS", {}).get(
                "U2F", "Classical Security Key"
            ),
        }
        return HttpResponse("RECOVERY")
    return HttpResponse("OK")


def sign(username):
    u2f_devices = [
        d.properties["device"]
        for d in User_Keys.objects.filter(username=username, key_type="U2F")
    ]
    challenge = begin_authentication(settings.U2F_APPID, u2f_devices)
    return [challenge.json, json.dumps(challenge.data_for_client)]


def verify(request):
    x = validate(request, request.session["base_username"])
    if x == True:
        return login(request)
    else:
        return x
