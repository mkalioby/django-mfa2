from django.shortcuts import render,render_to_response
from django.template.context_processors import csrf
import datetime,random
from random import randint
from .models import *
from django.template.context import RequestContext
from .views import login
from .Common import send
def sendEmail(request,username,secret):
    from django.contrib.auth import get_user_model
    User = get_user_model()
    key = getattr(User, 'USERNAME_FIELD', 'username')
    kwargs = {key: username}
    user = User.objects.get(**kwargs)
    res=render_to_response("mfa_email_token_template.html",{"request":request,"user":user,'otp':secret})
    return  send([user.email],"OTP", res.content)

def start(request):
    context = csrf(request)
    if request.method == "POST":
        if request.session["email_secret"] == request.POST["otp"]:
            uk=User_Keys()
            uk.username=request.user.username
            uk.key_type="Email"
            uk.enabled=1
            uk.save()
            from django.http import HttpResponseRedirect
            from django.core.urlresolvers import reverse
            return HttpResponseRedirect(reverse('mfa_home'))
        context["invalid"] = True
    else:
        request.session["email_secret"] = str(randint(0,100000))
        if sendEmail(request, request.user.username, request.session["email_secret"]):
            context["sent"] = True
    return render_to_response("Email/Add.html", context, context_instance=RequestContext(request))
def auth(request):
    context=csrf(request)
    if request.method=="POST":
        if request.session["email_secret"]==request.POST["otp"].strip():
            mfa = {"verified": True, "method": "Email"}
            if getattr(settings, "MFA_RECHECK", False):
                mfa["next_check"] = int((datetime.datetime.now() + datetime.timedelta(
                    seconds = random.randint(settings.MFA_RECHECK_MIN, settings.MFA_RECHECK_MAX))).strftime("%s"))
            request.session["mfa"] = mfa
            uk=User_Keys.objects.get(username=request.session["base_username"],key_type="Email")
            from django.utils import timezone
            uk.last_used=timezone.now()
            uk.save()
            return login(request)
        context["invalid"]=True
    else:
        request.session["email_secret"] = str(randint(0, 100000))
        if sendEmail(request, request.session["base_username"], request.session["email_secret"]):
            context["sent"] = True
    return render_to_response("Email/Auth.html", context, context_instance = RequestContext(request))