from django.conf import settings
from django.core.mail import EmailMessage

def send(to,subject,body):
    from_email_address = settings.EMAIL_HOST_USER
    if '@' not in from_email_address:
        from_email_address = settings.DEFAULT_FROM_EMAIL
    From = "%s <%s>" % (settings.EMAIL_FROM, from_email_address)
    email = EmailMessage(subject,body,From,to)
    email.content_subtype = "html"
    return email.send(False)