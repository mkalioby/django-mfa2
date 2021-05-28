from django.conf import settings
from django.core.mail import EmailMessage
try:
    from django.urls import reverse
except:
    from django.core.urlresolver import reverse

def send(to,subject,body):
    from_email_address = settings.EMAIL_HOST_USER
    if '@' not in from_email_address:
        from_email_address = settings.DEFAULT_FROM_EMAIL
    From = "%s <%s>" % (settings.EMAIL_FROM, from_email_address)
    email = EmailMessage(subject,body,From,to)
    email.content_subtype = "html"
    return email.send(False)

def get_redirect_url():
    return {"redirect_html": reverse(getattr(settings, 'MFA_REDIRECT_AFTER_REGISTRATION', 'mfa_home')),
            "reg_success_msg":getattr(settings,"MFA_SUCCESS_REGISTRATION_MSG")}
