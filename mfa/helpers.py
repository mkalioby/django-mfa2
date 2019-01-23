import pyotp
from .models import *
from . import TrustedDevice, U2F, FIDO2, totp
import simplejson
from django.shortcuts import HttpResponse
from mfa.views import verify,goto
def has_mfa(request,username):
    if User_Keys.objects.filter(username=username,enabled=1).count()>0:
        return verify(request, username)
    return False

def is_mfa(request,ignore_methods=[]):
    if request.session.get("mfa",{}).get("verified",False):
        if not request.session.get("mfa",{}).get("method",None) in ignore_methods:
            return True
    return False

def recheck(request):
    method=request.session.get("mfa",{}).get("method",None)
    if not method:
        return HttpResponse(simplejson.dumps({"res":False}),content_type="application/json")
    if method=="Trusted Device":
        return HttpResponse(simplejson.dumps({"res":TrustedDevice.verify(request)}),content_type="application/json")
    elif method=="U2F":
        return HttpResponse(simplejson.dumps({"html": U2F.recheck(request).content}), content_type="application/json")
    elif method == "FIDO2":
        return HttpResponse(simplejson.dumps({"html": FIDO2.recheck(request).content}), content_type="application/json")
    elif method=="TOTP":
        return HttpResponse(simplejson.dumps({"html": totp.recheck(request).content}), content_type="application/json")



