from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.contrib.auth import authenticate,login,logout
def loginView(request):
    context={}
    if request.method=="POST":
        username=request.POST["username"]
        password=request.POST["password"]
        user=authenticate(username=username,password=password)
        if user:
            login(request,user)
            return HttpResponseRedirect(reverse('home'))
        context["invalid"]=True
    return render(request, "login.html", context)


def logoutView(request):
    logout(request)
    return  render(request,"logout.html",{})