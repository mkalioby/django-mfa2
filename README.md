# django-mfa2
A Django app that handles MFA, it supports TOTP, U2F, FIDO2 U2F (Web Authn), Email Tokens , and Trusted Devices

[![PyPI version](https://badge.fury.io/py/django-mfa2.svg)](https://badge.fury.io/py/django-mfa2)

Web Authencation API (WebAuthn) is state-of-the art techology that is expected to replace passwords.

![Andriod Fingerprint](https://cdn-images-1.medium.com/max/800/1*1FWkRE8D7NTA2Kn1DrPjPA.png)

For FIDO2, **security keys**, **Apple's Touch ID (Chrome)** and **android-safetynet** are supported.

In English :), It allows you to verify the user by security keys on PC, Laptops, Touch ID on Macboks (Chrome) and Fingerprint/PIN on Andriod Phones.

Trusted device is a mode for the user to add a device that doesn't support security keys like iOS and andriod without fingerprints or NFC.

**Note**: `U2F and FIDO2 can only be served under secure context (https)`

Package tested with Django 1.8, Django 2.1 on Python 2.7 and Python 3.5+ but it was not checked with any version in between but open for issues.

Depends on

* pyotp
* python-u2flib-server
* ua-parser
* user-agents
* python-jose
* fido2==0.5


# Installation
1. `pip install django-mfa2`
1. in your settings.py add the application to your installed apps
   ```python
   INSTALLED_APPS=(
   '......',
   'mfa',
   '......')
   ```
1. Collect Static Files
`python manage.py collectstatic`
1. Add the following settings to your file

   ```python 
   MFA_UNALLOWED_METHODS=()   # Methods that shouldn't be allowed for the user
   MFA_LOGIN_CALLBACK=""      # A function that should be called by username to login the user in session
   MFA_RECHECK=True           # Allow random rechecking of the user
   MFA_RECHECK_MIN=10         # Minimum interval in seconds
   MFA_RECHECK_MAX=30         # Maximum in seconds
   MFA_QUICKLOGIN=True        # Allow quick login for returning users by provide only their 2FA
   MFA_HIDE_DISABLE=('FIDO2',)     # Can the user disable his key (Added in 1.2.0).   

   TOKEN_ISSUER_NAME="PROJECT_NAME"      #TOTP Issuer name

   U2F_APPID="https://localhost"    #URL For U2F
   FIDO_SERVER_ID=u"localehost"      # Server rp id for FIDO2, it the full domain of your project
   FIDO_SERVER_NAME=u"PROJECT_NAME"
   FIDO_LOGIN_URL=BASE_URL
   ```
   **Method Names**
   * U2F
   * FIDO2
   * TOTP
   * Trusted_Devices
   * Email
   
   **Note**: Starting version 1.1, ~~FIDO_LOGIN_URL~~ isn't required for FIDO2 anymore.
   
1. Break your login function

   Usually your login function will check for username and password, log the user in if the username and password are correct and create the user session, to support mfa, this has to change
   
      * authenticate the user
      * if username and password are correct , check if the user has mfa or not
          * if user has mfa then redirect to mfa page
          * if user doesn't have mfa then call your function to create the user session

   ```python
    def login(request): # this function handles the login form POST
       user = auth.authenticate(username=username, password=password)  
       if user is not None: # if the user object exist
            from mfa.helpers import has_mfa
            res =  has_mfa(username = username,request=request) # has_mfa returns false or HttpResponseRedirect
            if res:
                return res
            return log_user_in(request,username=user.username) 
            #log_user_in is a function that handles creatung user session, it should be in the setting file as MFA_CALLBACK
     ```
1. Add mfa to urls.py
   ```python 
   import mfa
   import mfa.TrustedDevice
   urls_patterns= [
   '...',
   url(r'^mfa/', include('mfa.urls')),
   url(r'devices/add$', mfa.TrustedDevice.add,name="mfa_add_new_trusted_device"), # This short link to add new trusted device
   '....',
    ]
    ```
1. Provide `mfa_auth_base.html` in your templaes with block called 'head' and 'content'
    The template will be included during the user login.
    If you will use Email Token method, then you have to provide template named `mfa_email_token_template.html` that will content the format of the email with parameter named `user` and `otp`.
1. To match the look and feel of your project, MFA includes `base.html` but it needs blocks named `head` & `content` to added its content to it.
1. Somewhere in your app, add a link to 'mfa_home'
```<li><a href="{% url 'mfa_home' %}">Security</a> </li>```

For Example, See https://github.com/mkalioby/AutoDeploy/commit/5f1d94b1804e0aa33c79e9e8530ce849d9eb78cc in AutDeploy Project

# Going Passwordless

To be able to go passwordless for returning users, create a cookie  named 'base_username' containing username as shown in snippet below
```python
    response = render(request, 'Dashboard.html', context))
    if request.session.get("mfa",{}).get("verified",False)  and getattr(settings,"MFA_QUICKLOGIN",False):
        if request.session["mfa"]["method"]!="Trusted Device":
            response.set_cookie("base_username", request.user.username, path="/",max_age = 15*24*60*60)
    return response
```

Second, update the GET part of your login view
```python
    if "mfa" in settings.INSTALLED_APPS and getattr(settings,"MFA_QUICKLOGIN",False) and request.COOKIES.get('base_username'):
        username=request.COOKIES.get('base_username')
        from mfa.helpers import has_mfa
        res =  has_mfa(username = username,request=request,)
        if res: return res
        ## continue and return the form.
```
# Checking MFA on Client Side

Sometimes you like to verify that the user is still there so simple you can ask django-mfa2 to check that for you

```html
    {% include 'mfa_check.html' %}
```
````js
function success_func() {
  //logic if mfa check succeeds
}
function fail_func() {
  //logic if mfa check fails
}
function some_func() {
    recheck_mfa(success_func,fail_func,MUST_BE_MFA)
    //MUST_BE_MFA true or false, if the user must has with MFA
  }

````
