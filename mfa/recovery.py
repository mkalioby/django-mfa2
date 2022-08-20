from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.http import HttpResponse
from .Common import get_redirect_url
from .models import *
import simplejson
from django.conf import settings
import random
import string
import logging

def invalidate_token(key):
    key.enabled = 0
    key.save()

def token_left(request, username=None):
    if not username:
        username = request.user.username
    return len(User_Keys.objects.filter(username=username, key_type="RECOVERY", enabled=True))

def delTokens(request):
    #Only when all MFA have been deactivated, or to generate new !
    for key in User_Keys.objects.filter(username=request.user.username, key_type = "RECOVERY"):
        if key.username == request.user.username:
            key.delete()

def newTokens(username):
    for newkey in range(5):
            token = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(6))
            uk=User_Keys()
            uk.username=username
            uk.properties={"secret_key":token}
            uk.key_type="RECOVERY"
            uk.enabled=True
            uk.save()

def genTokens(request, softGen=False):
    if not softGen or (softGen and token_left(request) == 0):
        #Delete old ones
        delTokens(request)
        number = 5
        #Then generate new one
        newTokens(request.user.username)
    return HttpResponse("Success")


def verify_login(username,token):
    for key in User_Keys.objects.filter(username=username, key_type = "RECOVERY"):
        logging.critical(key.properties["secret_key"])
        if key.properties["secret_key"] == token and key.enabled:
            invalidate_token(key)
            newRecoveryGen = False 
            if token_left(None, username) == 0:
                newRecoveryGen = True
                newTokens(username)
            return [True, key.id, newRecoveryGen]
    return [False]

def getTokens(request):
    tokens = []
    enable = []
    for key in User_Keys.objects.filter(username=request.user.username, key_type = "RECOVERY"):
        tokens.append(key.properties["secret_key"])
        enable.append(1 if key.enabled else 0)
    return HttpResponse(simplejson.dumps({"keys":tokens, "enable":enable}))

@never_cache
def start(request):
    """Start Managing recovery tokens"""
    return render(request,"RECOVERY/Add.html",get_redirect_url())