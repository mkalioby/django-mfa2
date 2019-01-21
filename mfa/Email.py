from django.shortcuts import render,render_to_response
from django.template.context_processors import csrf
import os
from .models import *
from django.template.context import RequestContext
from .views import login

def sendEmail(request,username,secret):
    from django.contrib.auth import get_user_model
    User = get_user_model()
    user=User.objects.get(username=username)
    res=render_to_response("mfa_email_token_template",{"request":request,"user":user,'otp':secret})
    from django.conf import settings
    from django.core.mail import EmailMessage
    From = "%s <%s>" % (settings.EMAIL_FROM, settings.EMAIL_HOST_USER)
    email = EmailMessage("OTP",res.content,From,user.email )
    email.content_subtype = "html"
    return email.send(False)

def start(request):
    context = csrf(request)
    if request.method == "POST":
        if request.session["email_secret"] == request.post["otp"]:
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
        request.session["email_secret"] = os.urandom(6)
        if sendEmail(request, request.session["base_username"], request.session["email_secret"]):
            context["sent"] = True
    return render_to_response("Email/Add.html", context, context_instance=RequestContext(request))
def auth(request):
    context=csrf(request)
    if request.method=="POST":
        if request.session["email_secret"]==request.post["otp"].strip():
            return login(request)
        context["invalid"]=True
    else:
        request.session["email_secret"]=os.urandom(6)
        if sendEmail(request,request.session["base_username"],request.session["email_secret"]):
            context["sent"]=True
    return render_to_response("Email/Auth.html", context, context_instance = RequestContext(request))