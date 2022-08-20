from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.http import HttpResponse
from .Common import get_redirect_url
from .models import *
import simplejson
import random
import string


#TODO : 
# - Show authtificator panel on login everytime if RECOVERY is not deactivated
# - Generation abuse checks

def token_left(request):
    uk = User_Keys.objects.filter(username=request.user.username, key_type="RECOVERY", enabled=True)
    keyLeft=0
    for key in uk:
        keyEnabled = key.properties["enabled"]
        for i in range(len(keyEnabled)):
            if keyEnabled[i]:
                keyLeft += 1
    return keyLeft

def delTokens(request):
    #Only when all MFA have been deactivated, or to generate new !
    #We iterate only to clean if any error happend and multiple entry of RECOVERY created for one user
    for key in User_Keys.objects.filter(username=request.user.username, key_type = "RECOVERY"):
        if key.username == request.user.username:
            key.delete()

def newTokens(username):
    # Separated from genTokens to be able to regenerate codes after login if last code has been used
    newKeys = []
    for i in range(5):
            token = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(10))
            newKeys.append(token)
    uk=User_Keys()
    uk.username=username
    uk.properties={"secret_keys":newKeys, "enabled":[True for j in range(5)]}
    uk.key_type="RECOVERY"
    uk.save()

def genTokens(request, softGen=False):
    if not softGen or (softGen and token_left(request) == 0):
        #Delete old ones
        delTokens(request)
        number = 5
        #Then generate new one
        newTokens(request.user.username)
    return HttpResponse("Success")


def verify_login(request, username,token):
    for key in User_Keys.objects.filter(username=username, key_type = "RECOVERY"):
        secret_keys = key.properties["secret_keys"]
        for i in range(len(secret_keys)):
            if token == secret_keys[i] and key.properties["enabled"][i]:
                key.properties["enabled"][i] = False
                key.save()
                if token_left(request) == 0:
                    newTokens(username)
                return [True, key.id]
    return [False]

def getTokens(request):
    tokens = []
    enable = []
    for key in User_Keys.objects.filter(username=request.user.username, key_type = "RECOVERY"):
        secret_keys = key.properties["secret_keys"]
        for i in range(len(secret_keys)):
            tokens.append(secret_keys[i])
            enable.append(key.properties["enabled"][i])
    return HttpResponse(simplejson.dumps({"keys":tokens, "enable":enable}))

@never_cache
def start(request):
    """Start Managing recovery tokens"""
    return render(request,"RECOVERY/Add.html",get_redirect_url())