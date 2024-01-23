# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


def update_owned_by_enterprise(apps, schema_editor):
    user_keys = apps.get_model("mfa", "user_keys")
    user_keys.objects.filter(key_type="FIDO2").update(
        owned_by_enterprise=getattr(settings, "MFA_OWNED_BY_ENTERPRISE", False)
    )


class Migration(migrations.Migration):
    dependencies = [
        ("mfa", "0008_user_keys_last_used"),
    ]

    operations = [
        migrations.AddField(
            model_name="user_keys",
            name="owned_by_enterprise",
            field=models.NullBooleanField(default=None),
        ),
        migrations.RunPython(update_owned_by_enterprise),
    ]
