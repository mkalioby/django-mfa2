import json

from fido2.server import Fido2Server, PublicKeyCredentialRpEntity
from fido2.webauthn import RegistrationResponse
from django.template.context_processors import csrf
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render

from django.http import HttpResponse
from django.conf import settings
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import AttestedCredentialData
from .views import login, reset_cookie
from .models import User_Keys
import datetime
from .Common import get_redirect_url, set_next_recheck
from django.utils import timezone
import fido2.features
from django.http import JsonResponse


def enable_json_mapping():
    try:
        fido2.features.webauthn_json_mapping.enabled = True
    except:
        pass


def recheck(request):
    """Starts FIDO2 recheck"""
    context = csrf(request)
    context["mode"] = "recheck"
    request.session["mfa_recheck"] = True
    return render(request, "FIDO2/recheck.html", context)


def getServer():
    """Get Server Info from settings and returns a Fido2Server"""
    from mfa import AttestationPreference

    rp = PublicKeyCredentialRpEntity(
        id=settings.FIDO_SERVER_ID, name=settings.FIDO_SERVER_NAME
    )
    attestation = getattr(
        settings, "MFA_FIDO2_ATTESTATION_PREFERENCE", AttestationPreference.NONE
    )
    return Fido2Server(rp, attestation=attestation)


def begin_registeration(request):
    """Starts registering a new FIDO Device, called from API"""
    enable_json_mapping()
    server = getServer()
    from mfa import ResidentKey

    resident_key = getattr(settings, "MFA_FIDO2_RESIDENT_KEY", ResidentKey.DISCOURAGED)
    auth_attachment = getattr(settings, "MFA_FIDO2_AUTHENTICATOR_ATTACHMENT", None)
    user_verification = getattr(settings, "MFA_FIDO2_USER_VERIFICATION", None)
    registration_data, state = server.register_begin(
        {
            "id": request.user.username.encode("utf8"),
            "name": request.user.username,
            "displayName": request.user.username,
        },
        getUserCredentials(request.user.username),
        user_verification=user_verification,
        resident_key_requirement=resident_key,
        authenticator_attachment=auth_attachment,
    )
    request.session["fido2_state"] = state
    return JsonResponse(dict(registration_data))
    # return HttpResponse(cbor.encode(registration_data), content_type = 'application/octet-stream')


@csrf_exempt
def complete_reg(request):
    """Completes the registration, called by API"""
    try:
        if not "fido2_state" in request.session:
            return JsonResponse(
                {
                    "status": "ERR",
                    "message": "FIDO Status can't be found, please try again",
                }
            )
        enable_json_mapping()
        data = json.loads(request.body)
        server = getServer()
        auth_data = server.register_complete(
            request.session["fido2_state"], response=data
        )
        registration = RegistrationResponse.from_dict(data)
        attestation_object = registration.response.attestation_object
        # auth_data = attestation_object.auth_data
        att_obj = attestation_object

        encoded = websafe_encode(auth_data.credential_data)
        uk = User_Keys()
        uk.username = request.user.username
        uk.properties = {
            "device": encoded,
            "type": att_obj.fmt,
        }
        uk.owned_by_enterprise = getattr(settings, "MFA_OWNED_BY_ENTERPRISE", False)
        uk.key_type = "FIDO2"
        if auth_data.credential_data.credential_id:
            uk.user_handle = auth_data.credential_data.credential_id
        uk.save()
        if (
            getattr(settings, "MFA_ENFORCE_RECOVERY_METHOD", False)
            and not User_Keys.objects.filter(
                key_type="RECOVERY", username=request.user.username
            ).exists()
        ):
            request.session["mfa_reg"] = {
                "method": "FIDO2",
                "name": getattr(settings, "MFA_RENAME_METHODS", {}).get(
                    "FIDO2", "FIDO2"
                ),
            }
            return JsonResponse({"status": "RECOVERY"})
        else:
            return JsonResponse({"status": "OK"})
    except Exception as exp:
        import traceback

        print(traceback.format_exc())
        return JsonResponse(
            {"status": "ERR", "message": "Error on server, please try again later"},
            status=500,
        )


def start(request):
    """Start Registration a new FIDO Token"""
    context = csrf(request)
    context.update(get_redirect_url())
    context["method"] = {
        "name": getattr(settings, "MFA_RENAME_METHODS", {}).get(
            "FIDO2", "FIDO2 Security Key"
        )
    }
    context["RECOVERY_METHOD"] = getattr(settings, "MFA_RENAME_METHODS", {}).get(
        "RECOVERY", "Recovery codes"
    )
    return render(request, "FIDO2/Add.html", context)


def getUserCredentials(username):
    return [
        AttestedCredentialData(websafe_decode(uk.properties["device"]))
        for uk in User_Keys.objects.filter(username=username, key_type="FIDO2")
    ]


def auth(request):
    context = csrf(request)
    return render(request, "FIDO2/Auth.html", context)


def authenticate_begin(request):
    enable_json_mapping()
    server = getServer()
    credentials = []
    username = None
    if "base_username" in request.session:
        username = request.session["base_username"]
    if request.user.is_authenticated:
        username = request.user.username
    if username:
        credentials = getUserCredentials(
            request.session.get("base_username", request.user.username)
        )
    auth_data, state = server.authenticate_begin(credentials)
    request.session["fido2_state"] = state
    return JsonResponse(dict(auth_data))


@csrf_exempt
def authenticate_complete(request):
    try:
        enable_json_mapping()
        credentials = []
        username = None
        keys = None
        if "base_username" in request.session:
            username = request.session["base_username"]
        if request.user.is_authenticated:
            username = request.user.username
        server = getServer()
        data = json.loads(request.body)
        userHandle = data.get("response", {}).get("userHandle")
        credential_id = data["id"]

        if userHandle:
            if User_Keys.objects.filter(username=userHandle).exists():
                credentials = getUserCredentials(userHandle)
                username = userHandle
            else:
                keys = User_Keys.objects.filter(user_handle=userHandle)
                if keys.exists():
                    credentials = [
                        AttestedCredentialData(
                            websafe_decode(keys[0].properties["device"])
                        )
                    ]
        elif credential_id and username is None:
            keys = User_Keys.objects.filter(user_handle=credential_id)
            if keys.exists():
                credentials = [
                    AttestedCredentialData(websafe_decode(keys[0].properties["device"]))
                ]
        else:
            credentials = getUserCredentials(username)

        try:
            cred = server.authenticate_complete(
                request.session.pop("fido2_state"),
                credentials=credentials,
                response=data,
            )
        except ValueError:
            return (
                JsonResponse(
                    {
                        "status": "ERR",
                        "message": "Wrong challenge received, make sure that this is your security and try again.",
                    },
                    status=400,
                ),
            )

        except Exception as excep:
            return JsonResponse({"status": "ERR", "message": str(excep)}, status=500)

        if request.session.get("mfa_recheck", False):
            request.session["mfa"]["rechecked_at"] = time.time()
            request.session["mfa"].update(set_next_recheck())
            return JsonResponse({"status": "OK"})

        else:
            if keys is None:
                keys = User_Keys.objects.filter(
                    username=username, key_type="FIDO2", enabled=1
                )
            for k in keys:
                if (
                    AttestedCredentialData(
                        websafe_decode(k.properties["device"])
                    ).credential_id
                    == cred.credential_id
                ):
                    k.last_used = timezone.now()
                    k.save()
                    mfa = {"verified": True, "method": "FIDO2", "id": k.id}
                    mfa.update(set_next_recheck())
                    request.session["mfa"] = mfa
                    try:
                        authenticated = request.user.is_authenticated
                    except:
                        authenticated = request.user.is_authenticated()
                    if not authenticated:
                        res = login(request, k.username)
                        if not "location" in res:
                            return reset_cookie(request)
                        return JsonResponse(
                            {"status": "OK", "redirect": res["location"]}
                        )

                    return JsonResponse({"status": "OK"})

    except Exception as exp:
        import traceback

        print(traceback.format_exc())
        return JsonResponse({"status": "ERR", "message": str(exp)}, status=500)
