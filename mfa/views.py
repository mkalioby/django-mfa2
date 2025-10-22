import importlib

from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect


try:
    from django.urls import reverse
except:
    from django.core.urlresolvers import reverse  # pyre-ignore[21]
from django.contrib.auth.decorators import login_required
def login(request, username=None):
    """
    Handles user login by validating credentials and initiating the authentication process.

    Args:
        request (HttpRequest): The HTTP request object containing user credentials.
        username (str, optional): Username to login. Defaults to None.

    Returns:
        HttpResponse: A response indicating the success or failure of the login attempt.
    """

    from django.conf import settings

    callable_func = __get_callable_function__(settings.MFA_LOGIN_CALLBACK)
    if not username:
        username = request.session["base_username"]
    return callable_func(request, username=username)

from django.conf import settings
from user_agents import parse
from . import TrustedDevice
from .models import User_Keys


@login_required
def index(request):
    """
    Displays the list of multi-factor authentication keys for the logged-in user.

    Args:
        request (HttpRequest): The HTTP request object from the logged-in user.

    Returns:
        HttpResponse: Renders the MFA.html template with the user's keys and settings.
    """

    keys = []
    context = {
        "keys": User_Keys.objects.filter(username=request.user.username),
        "UNALLOWED_AUTHEN_METHODS": settings.MFA_UNALLOWED_METHODS,
        "HIDE_DISABLE": getattr(settings, "MFA_HIDE_DISABLE", []),
        "RENAME_METHODS": getattr(settings, "MFA_RENAME_METHODS", {}),
    }
    name_map = getattr(settings, "MFA_RENAME_METHODS", {})
    for k in context["keys"]:
        k.name = name_map.get(k.key_type, k.key_type)
        if k.key_type == "Trusted Device":
            setattr(k, "device", parse(k.properties.get("user_agent", "-----")))
        elif k.key_type == "FIDO2":
            setattr(k, "device", k.properties.get("type", "----"))
        elif k.key_type == "RECOVERY":
            context["recovery"] = k
            continue
        elif k.key_type == "Email" and getattr(
            settings, "MFA_ENFORCE_EMAIL_TOKEN", False
        ):
            continue

        keys.append(k)
    context["keys"] = keys
    return render(request, "MFA.html", context)


def verify(request, username):
    """
    Verifies the available MFA methods for a user and redirects appropriately.

    Args:
        request (HttpRequest): The HTTP request object.
        username (str): The username of the user being verified.

    Returns:
        HttpResponse or HttpResponseRedirect: Redirects to the next MFA step or shows method selection.
    """

    # request.session["base_password"] = password
    keys = User_Keys.objects.filter(username=username, enabled=1)
    methods = list(set([k.key_type for k in keys]))

    if "Trusted Device" in methods and not request.session.get(
        "checked_trusted_device", False
    ):
        if TrustedDevice.verify(request):
            return login(request)
        methods.remove("Trusted Device")
    request.session["mfa_methods"] = methods
    if len(methods) == 0 and getattr(settings, "MFA_ENFORCE_EMAIL_TOKEN", False):
        methods = ["email"]
    if len(methods) == 1:
        return HttpResponseRedirect(reverse(methods[0].lower() + "_auth"))
    if getattr(settings, "MFA_ALWAYS_GO_TO_LAST_METHOD", False):
        keys = keys.exclude(last_used__isnull=True).order_by("-last_used")
        if keys.count() > 0:
            return HttpResponseRedirect(reverse(keys[0].key_type.lower() + "_auth"))
    return show_methods(request)


def show_methods(request):
    """
    Renders a page to let the user select an MFA method if multiple are available.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: Renders the select_mfa_method.html template.
    """

    return render(
        request,
        "select_mfa_method.html",
        {"RENAME_METHODS": getattr(settings, "MFA_RENAME_METHODS", {})},
    )


def reset_cookie(request):
    """
    Deletes the base_username cookie and redirects the user to the login page.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponseRedirect: Redirects to the LOGIN_URL after deleting the cookie.
    """

    response = HttpResponseRedirect(settings.LOGIN_URL)
    response.delete_cookie("base_username")
    return response


def login(request, username=None):
    from django.conf import settings

    callable_func = __get_callable_function__(settings.MFA_LOGIN_CALLBACK)
    if not username:
        username = request.session["base_username"]
    return callable_func(request, username=username)


@login_required
def delKey(request):
    """
    Deletes a user's MFA key if it belongs to the logged-in user.

    Args:
        request (HttpRequest): The HTTP request object containing the key ID.

    Returns:
        HttpResponse: Success or error message.
    """

    key = User_Keys.objects.get(id=request.POST["id"])
    if key.username == request.user.username:
        key.delete()
        return HttpResponse("Deleted Successfully")
    else:
        return HttpResponse("Error: This key doesn't exist")


def __get_callable_function__(func_path):
    if not "." in func_path:
        raise Exception("class Name should include modulename.classname")

    parsed_str = func_path.split(".")
    module_name, func_name = ".".join(parsed_str[:-1]), parsed_str[-1]
    imported_module = importlib.import_module(module_name)
    callable_func = getattr(imported_module, func_name)
    if not callable_func:
        raise Exception("Module does not have requested function")
    return callable_func


@login_required
def toggleKey(request):
    """
    Enables or disables an MFA key for the logged-in user.

    Args:
        request (HttpRequest): The HTTP request object containing the key ID.

    Returns:
        HttpResponse: Confirmation message or error message.
    """

    id = request.GET["id"]
    q = User_Keys.objects.filter(username=request.user.username, id=id)
    if q.count() == 1:
        key = q[0]
        if not key.key_type in settings.MFA_HIDE_DISABLE:
            key.enabled = not key.enabled
            key.save()
            return HttpResponse("OK")
        else:
            return HttpResponse("You can't change this method.")
    else:
        return HttpResponse("Error")


def goto(request, method):
    return HttpResponseRedirect(reverse(method.lower() + "_auth"))
