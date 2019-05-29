from fido2.client import ClientData
from fido2.server import Fido2Server, RelyingParty
from fido2.ctap2 import AttestationObject, AuthenticatorData
from django.template.context_processors import csrf
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render_to_response
from django.template.context import RequestContext
import simplejson
from fido2 import cbor
from django.http import HttpResponse
from django.conf import settings
from .models import *
from fido2.utils import websafe_decode,websafe_encode
from fido2.ctap2 import AttestedCredentialData
from .views import login
import datetime
from django.utils import timezone

def recheck(request):
    context = csrf(request)
    context["mode"]="recheck"
    return render_to_response("FIDO2/recheck.html", context, context_instance=RequestContext(request))


def getServer():
    rp = RelyingParty(settings.FIDO_SERVER_ID, settings.FIDO_SERVER_NAME)
    return Fido2Server(rp)
def begin_registeration(request):
    server = getServer()
    registration_data, state = server.register_begin({
        u'id': request.user.username.encode("utf8"),
        u'name': (request.user.first_name + " " + request.user.last_name),
        u'displayName': request.user.username,
    }, getUserCredentials(request.user.username))
    request.session['fido_state'] = state

    return HttpResponse(cbor.encode(registration_data),content_type='application/octet-stream')
@csrf_exempt
def complete_reg(request):
    try:
        data = cbor.decode(request.body)

        client_data = ClientData(data['clientDataJSON'])
        att_obj = AttestationObject((data['attestationObject']))
        server = getServer()
        auth_data = server.register_complete(
            request.session['fido_state'],
            client_data,
            att_obj
        )
        encoded = websafe_encode(auth_data.credential_data)
        uk=User_Keys()
        uk.username = request.user.username
        uk.properties = {"device":encoded,"type":att_obj.fmt,}
        uk.key_type = "FIDO2"
        uk.save()
        return HttpResponse(simplejson.dumps({'status': 'OK'}))
    except Exception as exp:
        from raven.contrib.django.raven_compat.models import client
        import traceback
        client.captureException()
        return HttpResponse(simplejson.dumps({'status': 'ERR',"message":"Error on server, please try again later"}))
def start(request):
    context = csrf(request)
    return render_to_response("FIDO2/Add.html", context, RequestContext(request))

def getUserCredentials(username):
    credentials = []
    for uk in User_Keys.objects.filter(username = username, key_type = "FIDO2"):
        credentials.append(AttestedCredentialData(websafe_decode(uk.properties["device"])))
    return credentials

def auth(request):
    context=csrf(request)
    return render_to_response("FIDO2/Auth.html",context,context_instance=RequestContext(request))

def authenticate_begin(request):
    server = getServer()
    credentials=getUserCredentials(request.session.get("base_username",request.user.username))
    auth_data, state = server.authenticate_begin(credentials)
    request.session['fido_state'] = state
    return HttpResponse(cbor.encode(auth_data),content_type="application/octet-stream")

@csrf_exempt
def authenticate_complete(request):
    credentials = []
    username=request.session.get("base_username",request.user.username)
    server=getServer()
    credentials=getUserCredentials(username)
    data = cbor.decode(request.body)
    credential_id = data['credentialId']
    client_data = ClientData(data['clientDataJSON'])
    auth_data = AuthenticatorData(data['authenticatorData'])
    signature = data['signature']

    cred = server.authenticate_complete(
        request.session.pop('fido_state'),
        credentials,
        credential_id,
        client_data,
        auth_data,
        signature
    )
    keys = User_Keys.objects.filter(username=username, key_type="FIDO2",enabled=1)
    import random
    for k in keys:
        if AttestedCredentialData(websafe_decode(k.properties["device"])).credential_id == cred.credential_id:
            k.last_used = timezone.now()
            k.save()
            mfa = {"verified": True, "method": "FIDO2"}
            if getattr(settings, "MFA_RECHECK", False):
                mfa["next_check"] = int((datetime.datetime.now()+ datetime.timedelta(
                seconds=random.randint(settings.MFA_RECHECK_MIN, settings.MFA_RECHECK_MAX))).strftime("%s"))
            request.session["mfa"] = mfa
            res=login(request)
            return HttpResponse(simplejson.dumps({'status':"OK","redirect":res["location"]}),content_type="application/json")
    return HttpResponse(simplejson.dumps({'status': "err"}),content_type="application/json")
