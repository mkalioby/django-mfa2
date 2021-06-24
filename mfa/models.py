from django.conf import settings
from django.db import models
from jose import jwt
from jsonfield import JSONField


class UserKey(models.Model):
    username = models.CharField(max_length=50)
    properties = JSONField(null=True)
    added_on = models.DateTimeField(auto_now_add=True)
    key_type = models.CharField(max_length=25, default="TOTP")
    enabled = models.BooleanField(default=True)
    expires = models.DateTimeField(null=True, default=None, blank=True)
    last_used = models.DateTimeField(null=True, default=None, blank=True)
    owned_by_enterprise = models.BooleanField(default=None, null=True, blank=True)

    def save(self, *args, **kwargs):
        if (
            self.key_type == "Trusted Device"
            and self.properties.get("signature", "") == ""
        ):
            self.properties["signature"] = jwt.encode(
                {"username": self.username, "key": self.properties["key"]},
                settings.SECRET_KEY,
            )
        super().save(*args, **kwargs)

    def __str__(self):
        return "%s -- %s" % (self.username, self.key_type)

    class Meta:
        app_label = "mfa"


class OTPTracker(models.Model):
    actor = models.CharField(
        max_length=50, help_text="Username"
    )  # named this way for indexing purpose.
    value = models.CharField(max_length=6)
    success = models.BooleanField(blank=True)
    done_on = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "mfa"
        indexes = [models.Index(fields=["actor"])]
