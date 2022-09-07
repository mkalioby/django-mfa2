from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.template.context_processors import csrf
import datetime,random
from random import randint
from .models import *
#from django.template.context import RequestContext
from .views import login
from .Common import send

def sendEmail(request,username,secret):
    """Send Email to the user after rendering `mfa_email_token_template`"""
    from django.contrib.auth import get_user_model
    User = get_user_model()
    key = getattr(User, 'USERNAME_FIELD', 'username')
    kwargs = {key: username}
    user = User.objects.get(**kwargs)
    res=render(request,"mfa_email_token_template.html",{"request":request,"user":user,'otp':secret})
    return send([user.email],"OTP", res.content.decode())

@never_cache
def start(request):
    """Start adding email as a 2nd factor"""
    context = csrf(request)
    if request.method == "POST":
        if request.session["email_secret"] == request.POST["otp"]:  #if successful
            uk=User_Keys()
            uk.username=request.user.username
            uk.key_type="Email"
            uk.enabled=1
            uk.save()
            from django.http import HttpResponseRedirect
            try:
                from django.core.urlresolvers import reverse
            except:
                from django.urls import reverse
            if getattr(settings, 'MFA_ENFORCE_RECOVERY_METHOD', False) and not User_Keys.objects.filter(
                    key_type="RECOVERY", username=request.user.username).exists():
                request.session["mfa_reg"] = {"method": "Email",
                                              "name": getattr(settings, "MFA_RENAME_METHODS", {}).get("Email", "Email")}
            else:
                return HttpResponseRedirect(reverse(getattr(settings,'MFA_REDIRECT_AFTER_REGISTRATION','mfa_home')))
        context["invalid"] = True
    else:
        request.session["email_secret"] = str(randint(0,100000))  #generate a random integer

        if sendEmail(request, request.user.username, request.session["email_secret"]):
            context["sent"] = True
    return render(request,"Email/Add.html", context)
@never_cache
def auth(request):
    """Authenticating the user by email."""
    context=csrf(request)
    if request.method=="POST":
        if request.session["email_secret"]==request.POST["otp"].strip():
            uk = User_Keys.objects.get(username=request.session["base_username"], key_type="Email")
            mfa = {"verified": True, "method": "Email","id":uk.id}
            if getattr(settings, "MFA_RECHECK", False):
                mfa["next_check"] = datetime.datetime.timestamp(datetime.datetime.now() + datetime.timedelta(
                    seconds = random.randint(settings.MFA_RECHECK_MIN, settings.MFA_RECHECK_MAX)))
            request.session["mfa"] = mfa

            from django.utils import timezone
            uk.last_used=timezone.now()
            uk.save()
            return login(request)
        context["invalid"]=True
    else:
        request.session["email_secret"] = str(randint(0, 100000))
        if sendEmail(request, request.session["base_username"], request.session["email_secret"]):
            context["sent"] = True
    return render(request,"Email/Auth.html", context)
