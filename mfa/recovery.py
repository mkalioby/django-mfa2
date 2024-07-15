import time
import random
import string


from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.template.context_processors import csrf
from django.utils import timezone
from django.contrib.auth.hashers import make_password, PBKDF2PasswordHasher
from django.http import HttpResponse, JsonResponse
from django.conf import settings
from .Common import get_redirect_url
from .models import User_Keys

USER_FRIENDLY_NAME = "Recovery Codes"


class Hash(PBKDF2PasswordHasher):
    algorithm = "pbkdf2_sha256_custom"
    iterations = getattr(settings, "RECOVERY_ITERATION", 1)


def delTokens(request):
    # Only when all MFA have been deactivated, or to generate new !
    # We iterate only to clean if any error happend and multiple entry of RECOVERY created for one user
    for key in User_Keys.objects.filter(
        username=request.user.username, key_type="RECOVERY"
    ):
        if key.username == request.user.username:
            key.delete()


def randomGen(n):
    return "".join(
        random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits)
        for _ in range(n)
    )


@never_cache
def genTokens(request):
    # Delete old ones
    delTokens(request)
    # Then generate new one
    salt = randomGen(15)
    hashedKeys = []
    clearKeys = []
    for i in range(5):
        token = randomGen(5) + "-" + randomGen(5)
        hashedToken = make_password(token, salt, "pbkdf2_sha256_custom")
        hashedKeys.append(hashedToken)
        clearKeys.append(token)
    uk = User_Keys()

    uk.username = request.user.username
    uk.properties = {"secret_keys": hashedKeys, "salt": salt}
    uk.key_type = "RECOVERY"
    uk.enabled = True
    uk.save()
    return JsonResponse({"keys": clearKeys})


def verify_login(request, username, token):
    for key in User_Keys.objects.filter(username=username, key_type="RECOVERY"):
        secret_keys = key.properties["secret_keys"]
        salt = key.properties["salt"]
        hashedToken = make_password(token, salt, "pbkdf2_sha256_custom")
        for i, token in enumerate(secret_keys):
            if hashedToken == token:
                secret_keys.pop(i)
                key.properties["secret_keys"] = secret_keys
                key.last_used = timezone.now()
                key.save()
                return [True, key.id, len(secret_keys) == 0]
    return [False]


def getTokenLeft(request):
    uk = User_Keys.objects.filter(username=request.user.username, key_type="RECOVERY")
    keyLeft = 0
    for key in uk:
        keyLeft += len(key.properties["secret_keys"])
    return JsonResponse({"left": keyLeft})


def recheck(request):
    context = csrf(request)
    context["mode"] = "recheck"
    if request.method == "POST":
        if verify_login(request, request.user.username, token=request.POST["recovery"])[
            0
        ]:
            request.session["mfa"]["rechecked_at"] = time.time()
            return JsonResponse({"recheck": True})

        else:
            return JsonResponse({"recheck": False})

    return render(request, "RECOVERY/recheck.html", context)


@never_cache
def auth(request):
    from .views import login

    context = csrf(request)
    if request.method == "POST":
        tokenLength = len(request.POST["recovery"])
        if tokenLength == 11 and "RECOVERY" not in settings.MFA_UNALLOWED_METHODS:
            # Backup code check
            resBackup = verify_login(
                request,
                request.session["base_username"],
                token=request.POST["recovery"],
            )
            if resBackup[0]:
                mfa = {
                    "verified": True,
                    "method": "RECOVERY",
                    "id": resBackup[1],
                    "lastBackup": resBackup[2],
                }
                request.session["mfa"] = mfa
                if resBackup[2]:
                    # If the last bakup code has just been used, we return a response insead of redirecting to login
                    context["lastBackup"] = True
                    return render(request, "RECOVERY/Auth.html", context)
                return login(request)
        context["invalid"] = True

    elif request.method == "GET":
        mfa = request.session.get("mfa")
        if mfa and mfa["verified"] and mfa["lastBackup"]:
            return login(request)

    return render(request, "RECOVERY/Auth.html", context)


@never_cache
def start(request):
    """Start Managing recovery tokens"""
    context = get_redirect_url()
    if "mfa_reg" in request.session:
        context["mfa_redirect"] = request.session["mfa_reg"]["name"]
    return render(request, "RECOVERY/Add.html", context)
