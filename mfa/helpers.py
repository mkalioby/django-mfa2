from django.http import JsonResponse
from django.conf import settings

from mfa.views import verify
from . import TrustedDevice, U2F, FIDO2, totp
from .models import User_Keys


def has_mfa(request, username):
    FORCE_EMAIL = getattr(settings, "MFA_ENFORCE_EMAIL_TOKEN", False)
    if (
        User_Keys.objects.filter(username=username, enabled=1).count() > 0
        or FORCE_EMAIL
    ):
        return verify(request, username)
    return False


def is_mfa(request, ignore_methods=[]):
    if request.session.get("mfa", {}).get("verified", False):
        if not request.session.get("mfa", {}).get("method", None) in ignore_methods:
            return True
    return False


def recheck(request):
    method = request.session.get("mfa", {}).get("method", None)
    if not method:
        return JsonResponse({"res": False})
    if method == "Trusted Device":
        return JsonResponse({"res": TrustedDevice.verify(request)})

    elif method == "U2F":
        return JsonResponse({"html": U2F.recheck(request).content})

    elif method == "FIDO2":
        return JsonResponse({"html": FIDO2.recheck(request).content})

    elif method == "TOTP":
        return JsonResponse({"html": totp.recheck(request).content})
