import string
import random
from django.shortcuts import render
from django.http import HttpResponse
from django.utils.translation import gettext
from django.template.context_processors import csrf
from .models import *
import user_agents
from django.utils import timezone
from django.utils.translation import gettext

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    x=''.join(random.choice(chars) for _ in range(size))
    if not User_Keys.objects.filter(properties__shas="$.key="+x).exists(): return x
    else: return id_generator(size,chars)

def getUserAgent(request):
    id=id=request.session.get("td_id",None)
    if id:
        tk=User_Keys.objects.get(id=id)
        if tk.properties.get("user_agent","")!="":
            ua = user_agents.parse(tk.properties["user_agent"])
            res = render(None, "TrustedDevices/user-agent.html", context={"ua":ua})
            return HttpResponse(res)
    return HttpResponse("")

def trust_device(request):
    tk = User_Keys.objects.get(id=request.session["td_id"])
    tk.properties["status"]="trusted"
    tk.save()
    del request.session["td_id"]
    return HttpResponse(gettext("OK"))

def checkTrusted(request):
    res = ""
    id=request.session.get("td_id","")
    if id!="":
        try:
            tk = User_Keys.objects.get(id=id)
            if tk.properties["status"] == "trusted": res = "OK"
        except:
            pass
    return HttpResponse(res)

def getCookie(request):
    tk = User_Keys.objects.get(id=request.session["td_id"])

    if tk.properties["status"] == "trusted":
        context={"added":True}
        response = render(request,"TrustedDevices/Done.html", context)
        from datetime import datetime, timedelta
        expires = datetime.now() + timedelta(days=180)
        tk.expires=expires
        tk.save()
        response.set_cookie("deviceid", tk.properties["signature"], expires=expires)
        return response

def add(request):
    context=csrf(request)
    if request.method=="GET":
        return render(request,"TrustedDevices/Add.html",context)
    else:
        key=request.POST["key"].replace("-","").replace(" ","").upper()
        context["username"] = request.POST["username"]
        context["key"] = request.POST["key"]
        trusted_keys=User_Keys.objects.filter(username=request.POST["username"],properties__has="$.key="+key)
        cookie=False
        if trusted_keys.exists():
            tk=trusted_keys[0]
            request.session["td_id"]=tk.id
            ua=request.META['HTTP_USER_AGENT']
            agent=user_agents.parse(ua)
            if agent.is_pc:
                context["invalid"]=gettext("This is a PC, it can't used as a trusted device.")
            else:
                tk.properties["user_agent"]=ua
                tk.save()
                context["success"]=True
            # tk.properties["user_agent"]=ua
            # tk.save()
            # context["success"]=True

        else:
            context["invalid"]=gettext("The username or key is wrong, please check and try again.")

        return  render(request,"TrustedDevices/Add.html", context)

def start(request):
    if User_Keys.objects.filter(username=request.user.username,key_type="Trusted Device").count()>= 2:
        return render(request,"TrustedDevices/start.html",{"not_allowed":True})
    td=None
    if not request.session.get("td_id",None):
        td=User_Keys()
        td.username=request.user.username
        td.properties={"key":id_generator(),"status":"adding"}
        td.key_type="Trusted Device"
        td.save()
        request.session["td_id"]=td.id
    try:
        if td==None: td=User_Keys.objects.get(id=request.session["td_id"])
        context={"key":td.properties["key"]}
    except:
        del request.session["td_id"]
        return start(request)
    return render(request,"TrustedDevices/start.html",context)

def send_email(request):
    body=render(request,"TrustedDevices/email.html",{}).content
    from .Common import send
    e=request.user.email
    if e=="":
        e=request.session.get("user",{}).get("email","")
    if e=="":
        res = gettext("User has no email on the system.")
    elif send([e],gettext("Add Trusted Device Link"),body):
        res=gettext("Sent Successfully")
    else:
        res=gettext("Error occured, please try again later.")
    return HttpResponse(res)


def verify(request):
    if request.COOKIES.get('deviceid',None):
        from jose import jwt
        json= jwt.decode(request.COOKIES.get('deviceid'),settings.SECRET_KEY)
        if json["username"].lower()== request.session['base_username'].lower():
            try:
                uk = User_Keys.objects.get(username=request.POST["username"].lower(), properties__has="$.key=" + json["key"])
                if uk.enabled and uk.properties["status"] == "trusted":
                    uk.last_used=timezone.now()
                    uk.save()
                    request.session["mfa"] = {"verified": True, "method": "Trusted Device","id":uk.id}
                    return True
            except:
                return False
    return False
