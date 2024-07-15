import datetime
from random import randint

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import EmailMessage

try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolver import reverse  # pyre-ignore[21]


def send(to, subject, body):
    from_email_address = settings.EMAIL_HOST_USER
    if "@" not in from_email_address:
        from_email_address = settings.DEFAULT_FROM_EMAIL
    From = "%s <%s>" % (settings.EMAIL_FROM, from_email_address)
    email = EmailMessage(subject, body, From, to)
    email.content_subtype = "html"
    return email.send(False)


def get_redirect_url():
    return {
        "redirect_html": reverse(
            getattr(settings, "MFA_REDIRECT_AFTER_REGISTRATION", "mfa_home")
        ),
        "reg_success_msg": getattr(settings, "MFA_SUCCESS_REGISTRATION_MSG"),
    }


def get_username_field():
    User = get_user_model()
    USERNAME_FIELD = getattr(User, "USERNAME_FIELD", "username")
    return User, USERNAME_FIELD


def set_next_recheck():
    if getattr(settings, "MFA_RECHECK", False):
        delta = datetime.timedelta(
            seconds=randint(settings.MFA_RECHECK_MIN, settings.MFA_RECHECK_MAX)
        )
        return {
            "next_check": datetime.datetime.timestamp(datetime.datetime.now() + delta)
        }
    return {}
