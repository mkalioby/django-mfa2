# Installation & Configuration
1. Install the package
  ```sh
   pip install django-mfa2
   ```
1. in your settings.py add the application to your installed apps
   ```python
   INSTALLED_APPS=(
   '......',
   'mfa',
   '......')
   ```
1. Add the following settings to your file
    ```python
    MFA_UNALLOWED_METHODS=()   # Methods that shouldn't be allowed for the user
    MFA_LOGIN_CALLBACK=""      # A function that should be called by username to login the user in session
    MFA_RECHECK=True           # Allow random rechecking of the user
    MFA_RECHECK_MIN=10         # Minimum interval in seconds
    MFA_RECHECK_MAX=30         # Maximum in seconds
    MFA_QUICKLOGIN=True        # Allow quick login for returning users by provide only their 2FA

    TOKEN_ISSUER_NAME="PROJECT_NAME"      #TOTP Issuer name

    U2F_APPID="https://localhost"    #URL For U2
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
1. Provide `mfa_auth_base.html` in your templates with block called 'head' and 'content'
    The template will be included during the user login.
    If you will use Email Token method, then you have to provide template named `mfa_email_token_template.html` that will content the format of the email with parameter named `user` and `otp`.
1. To match the look and feel of your project, MFA includes `base.html` but it needs blocks named `head` & `content` to added its content to it.
1. Somewhere in your app, add a link to 'mfa_home'
```<li><a href="{% url 'mfa_home' %}">Security</a> </li>```

Next, you need to [change your login code](change_login.md)
