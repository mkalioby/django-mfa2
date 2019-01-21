from django.shortcuts import render,render_to_response
from django.template.context_processors import csrf
import datetime,random
from random import randint
from .models import *
from django.template.context import RequestContext
from .views import login

def sendEmail(request,username,secret):
    from django.contrib.auth import get_user_model
    User = get_user_model()
    user=User.objects.get(username=username)
    print secret
    res=render_to_response("mfa_email_token_template.html",{"request":request,"user":user,'otp':secret})
    from django.conf import settings
    from django.core.mail import EmailMessage
    From = "%s <%s>" % (settings.EMAIL_FROM, settings.EMAIL_HOST_USER)
    email = EmailMessage("OTP",res.content,From,[user.email] )
    email.content_subtype = "html"
    return email.send(False)

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
        if sendEmail(request, request.session["base_username"], request.session["email_secret"]):
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
            return login(request)
        context["invalid"]=True
    else:
        request.session["email_secret"] = str(randint(0, 100000))
        if sendEmail(request, request.session["base_username"], request.session["email_secret"]):
            context["sent"] = True
    return render_to_response("Email/Auth.html", context, context_instance = RequestContext(request))