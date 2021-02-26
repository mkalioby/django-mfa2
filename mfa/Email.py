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
    from django.contrib.auth import get_user_model
    User = get_user_model()
    key = getattr(User, 'USERNAME_FIELD', 'username')
    kwargs = {key: username}
    user = User.objects.get(**kwargs)
    res=render(request,"mfa_email_token_template.html",{"request":request,"user":user,'otp':secret})
    return send([user.email],"OTP", res.content.decode())

@never_cache
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
            try:
                from django.core.urlresolvers import reverse
            except:
                from django.urls import reverse
            return HttpResponseRedirect(reverse('mfa_home'))
        context["invalid"] = True
    else:
        request.session["email_secret"] = str(randint(0,100000))
        if sendEmail(request, request.user.username, request.session["email_secret"]):
            context["sent"] = True
    return render(request,"Email/Add.html", context)
@never_cache
def auth(request):
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
