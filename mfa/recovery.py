from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.template.context_processors import csrf
from django.contrib.auth.hashers import make_password, PBKDF2PasswordHasher
from django.http import HttpResponse,FileResponse,HttpResponseNotFound
from .Common import get_redirect_url
from .models import *
import simplejson
import random
import string
import datetime

class Hash(PBKDF2PasswordHasher):
    algorithm = 'pbkdf2_sha256_custom'
    iterations = settings.RECOVERY_ITERATION

def delTokens(request):
    #Only when all MFA have been deactivated, or to generate new !
    #We iterate only to clean if any error happend and multiple entry of RECOVERY created for one user
    for key in User_Keys.objects.filter(username=request.user.username, key_type = "RECOVERY"):
        if key.username == request.user.username:
            key.delete()

def randomGen(n):
    return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(n))


@never_cache
def genTokens(request):
    #Delete old ones
    delTokens(request)
    #Then generate new one
    salt = randomGen(15)
    hashedKeys = []
    clearKeys = []
    for i in range(5):
            token = randomGen(5) + "-" + randomGen(5)
            hashedToken = make_password(token, salt, 'pbkdf2_sha256_custom')
            hashedKeys.append(hashedToken)
            clearKeys.append(token)
    uk=User_Keys()
    uk.username = request.user.username
    uk.properties={"secret_keys":hashedKeys, "salt":salt}
    uk.key_type="RECOVERY"
    uk.enabled = False
    uk.save()
    request.session["recovery_keys"]=clearKeys
    return HttpResponse(simplejson.dumps({"keys":clearKeys}))

def download_codes(request):
    if not "recovery_keys" in request.session:
        return HttpResponseNotFound("This page isn't valid anymore.")
    response = HttpResponse('\n'.join(request.session["recovery_keys"]),content_type='text/text')
    response['Content-Disposition'] = 'attachment; filename = Recovery Codes.txt'
    return response

def verify_login(request, username,token):
    key =  User_Keys.objects.filter(username=username, key_type = "RECOVERY")
    secret_keys = key.properties["secret_keys"]
    salt = key.properties["salt"]
    hashedToken = make_password(token, salt, "pbkdf2_sha256_custom")
    if hashedToken == secret_keys[0]:
        secret_keys.pop(0)
        key.properties["secret_keys"] = secret_keys
        key.save()
        return [True, key.id, len(secret_keys) == 0]
    return [False]

def getTokenLeft(request):
    uk = User_Keys.objects.filter(username=request.user.username, key_type = "RECOVERY")
    keyLeft=0
    for key in uk:
        keyLeft += len(key.properties["secret_keys"])
    return HttpResponse(simplejson.dumps({"left":keyLeft}))

@never_cache
def auth(request):
    from .views import login
    context=csrf(request)
    if request.method=="POST":
        tokenLength = len(request.POST["otp"])
        if tokenLength == 11 and "RECOVERY" not in settings.MFA_UNALLOWED_METHODS:
            #Backup code check
            resBackup=verify_login(request, request.session["base_username"], token=request.POST["otp"])
            if resBackup[0]:
                mfa = {"verified": True, "method": "RECOVERY","id":resBackup[1], "lastBackup":resBackup[2]}
                if getattr(settings, "MFA_RECHECK", False):
                    mfa["next_check"] = datetime.datetime.timestamp((datetime.datetime.now()
                                            + datetime.timedelta(
                                seconds=random.randint(settings.MFA_RECHECK_MIN, settings.MFA_RECHECK_MAX))))
                request.session["mfa"] = mfa
                if resBackup[2]:
                    #If the last bakup code has just been used, we return a response insead of redirecting to login
                    context["lastBackup"] = True
                    return render(request,"TOTP/Auth.html", context)                
                return login(request)
    elif request.method=="GET":
        mfa = request.session["mfa"]
        if mfa and mfa["verified"] and mfa["lastBackup"]:
            return login(request)

    context["invalid"]=True
    return render(request,"TOTP/Auth.html", context)

@never_cache
def start(request):
    """Start Managing recovery tokens"""
    return render(request,"RECOVERY/Add.html",get_redirect_url())