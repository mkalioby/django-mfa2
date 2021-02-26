from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.http import HttpResponse
from .models import *
from django.template.context_processors import csrf
import simplejson
from django.template.context import RequestContext
from django.conf import settings
import pyotp
from .views import login
import datetime
from django.utils import timezone
import random
def verify_login(request,username,token):
    for key in User_Keys.objects.filter(username=username,key_type = "TOTP"):
        totp = pyotp.TOTP(key.properties["secret_key"])
        if  totp.verify(token,valid_window = 30):
            key.last_used=timezone.now()
            key.save()
            return [True,key.id]
    return [False]

def recheck(request):
    context = csrf(request)
    context["mode"]="recheck"
    if request.method == "POST":
        if verify_login(request,request.user.username, token=request.POST["otp"]):
            import time
            request.session["mfa"]["rechecked_at"] = time.time()
            return HttpResponse(simplejson.dumps({"recheck": True}), content_type="application/json")
        else:
            return HttpResponse(simplejson.dumps({"recheck": False}), content_type="application/json")
    return render(request,"TOTP/recheck.html", context)

@never_cache
def auth(request):
    context=csrf(request)
    if request.method=="POST":
        res=verify_login(request,request.session["base_username"],token = request.POST["otp"])
        if res[0]:
            mfa = {"verified": True, "method": "TOTP","id":res[1]}
            if getattr(settings, "MFA_RECHECK", False):
                mfa["next_check"] = datetime.datetime.timestamp((datetime.datetime.now()
                                         + datetime.timedelta(
                            seconds=random.randint(settings.MFA_RECHECK_MIN, settings.MFA_RECHECK_MAX))))
            request.session["mfa"] = mfa
            return login(request)
        context["invalid"]=True
    return render(request,"TOTP/Auth.html", context)



def getToken(request):
    secret_key=pyotp.random_base32()
    totp = pyotp.TOTP(secret_key)
    request.session["new_mfa_answer"]=totp.now()
    return HttpResponse(simplejson.dumps({"qr":pyotp.totp.TOTP(secret_key).provisioning_uri(str(request.user.username), issuer_name = settings.TOKEN_ISSUER_NAME),
                         "secret_key": secret_key}))
def verify(request):
    answer=request.GET["answer"]
    secret_key=request.GET["key"]
    totp = pyotp.TOTP(secret_key)
    if totp.verify(answer,valid_window = 60):
        uk=User_Keys()
        uk.username=request.user.username
        uk.properties={"secret_key":secret_key}
        #uk.name="Authenticatior #%s"%User_Keys.objects.filter(username=user.username,type="TOTP")
        uk.key_type="TOTP"
        uk.save()
        return HttpResponse("Success")
    else: return HttpResponse("Error")

@never_cache
def start(request):
    return render(request,"TOTP/Add.html",{})
