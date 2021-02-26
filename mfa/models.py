from django.db import models
from jsonfield import JSONField
from jose import jwt
from django.conf import settings
from jsonLookup import shasLookup, hasLookup
JSONField.register_lookup(shasLookup)
JSONField.register_lookup(hasLookup)


class User_Keys(models.Model):
    username=models.CharField(max_length = 50)
    properties=JSONField(null = True)
    added_on=models.DateTimeField(auto_now_add = True)
    key_type=models.CharField(max_length = 25,default = "TOTP")
    enabled=models.BooleanField(default=True)
    expires=models.DateTimeField(null=True,default=None,blank=True)
    last_used=models.DateTimeField(null=True,default=None,blank=True)
    owned_by_enterprise=models.NullBooleanField(default=None,null=True,blank=True)

    def save(self, force_insert=False, force_update=False, using=None, update_fields=None):
        if self.key_type == "Trusted Device" and self.properties.get("signature","") == "":
            self.properties["signature"]= jwt.encode({"username": self.username, "key": self.properties["key"]}, settings.SECRET_KEY)
        super(User_Keys, self).save(force_insert=force_insert, force_update=force_update, using=using, update_fields=update_fields)

    def __unicode__(self):
        return "%s -- %s"%(self.username,self.key_type)

    def __str__(self):
        return self.__unicode__()

    class Meta:
        app_label='mfa'
