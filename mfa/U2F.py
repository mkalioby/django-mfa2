
from u2flib_server.u2f import (begin_registration, begin_authentication,
                               complete_registration, complete_authentication)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from django.shortcuts import render
import simplejson
#from django.template.context import RequestContext
from django.template.context_processors import csrf
from django.conf import settings
from django.http import HttpResponse
from .models import *
from .views import login
import datetime
from django.utils import timezone

def recheck(request):
    context = csrf(request)
    context["mode"]="recheck"
    s = sign(request.user.username)
    request.session["_u2f_challenge_"] = s[0]
    context["token"] = s[1]
    request.session["mfa_recheck"]=True
    return render(request,"U2F/recheck.html", context)

def process_recheck(request):
    x=validate(request,request.user.username)
    if x==True:
        import time
        request.session["mfa"]["rechecked_at"] = time.time()
        return HttpResponse(simplejson.dumps({"recheck":True}),content_type="application/json")
    return x

def check_errors(request, data):
    if "errorCode" in data:
        if data["errorCode"] == 0: return True
        if data["errorCode"] == 4:
            return HttpResponse("Invalid Security Key")
        if data["errorCode"] == 1:
            return auth(request)
    return True
def validate(request,username):
    import datetime, random

    data = simplejson.loads(request.POST["response"])

    res= check_errors(request,data)
    if res!=True:
        return res

    challenge = request.session.pop('_u2f_challenge_')
    device, c, t = complete_authentication(challenge, data, [settings.U2F_APPID])

    key=User_Keys.objects.get(username=username,properties__shas="$.device.publicKey=%s"%device["publicKey"])
    key.last_used=timezone.now()
    key.save()
    mfa = {"verified": True, "method": "U2F","id":key.id}
    if getattr(settings, "MFA_RECHECK", False):
        mfa["next_check"] = datetime.datetime.timestamp((datetime.datetime.now()
                                 + datetime.timedelta(
                    seconds=random.randint(settings.MFA_RECHECK_MIN, settings.MFA_RECHECK_MAX))))
    request.session["mfa"] = mfa
    return True

def auth(request):
    context=csrf(request)
    s=sign(request.session["base_username"])
    request.session["_u2f_challenge_"]=s[0]
    context["token"]=s[1]

    return render(request,"U2F/Auth.html")

def start(request):
    enroll = begin_registration(settings.U2F_APPID, [])
    request.session['_u2f_enroll_'] = enroll.json
    context=csrf(request)
    context["token"]=simplejson.dumps(enroll.data_for_client)
    return render(request,"U2F/Add.html",context)


def bind(request):
    import hashlib
    enroll = request.session['_u2f_enroll_']
    data=simplejson.loads(request.POST["response"])
    device, cert = complete_registration(enroll, data, [settings.U2F_APPID])
    cert = x509.load_der_x509_certificate(cert, default_backend())
    cert_hash=hashlib.md5(cert.public_bytes(Encoding.PEM)).hexdigest()
    q=User_Keys.objects.filter(key_type="U2F", properties__icontains= cert_hash)
    if q.exists():
        return HttpResponse("This key is registered before, it can't be registered again.")
    User_Keys.objects.filter(username=request.user.username,key_type="U2F").delete()
    uk = User_Keys()
    uk.username = request.user.username
    uk.owned_by_enterprise = getattr(settings, "MFA_OWNED_BY_ENTERPRISE", False)
    uk.properties = {"device":simplejson.loads(device.json),"cert":cert_hash}
    uk.key_type = "U2F"
    uk.save()
    return HttpResponse("OK")

def sign(username):
    u2f_devices=[d.properties["device"] for d in User_Keys.objects.filter(username=username,key_type="U2F")]
    challenge = begin_authentication(settings.U2F_APPID, u2f_devices)
    return [challenge.json,simplejson.dumps(challenge.data_for_client)]

def verify(request):
    x= validate(request,request.session["base_username"])
    if x==True:
        return login(request)
    else: return x
