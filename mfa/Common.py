from django.conf import settings
from django.core.mail import EmailMessage

def send(to,subject,body):
    From = "%s <%s>" % (settings.EMAIL_FROM, settings.EMAIL_HOST_USER)
    email = EmailMessage(subject,body,From,to)
    email.content_subtype = "html"
    return email.send(False)