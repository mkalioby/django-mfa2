# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings

class Migration(migrations.Migration):

    dependencies = [
        ('mfa', '0008_user_keys_last_used'),
    ]

    operations = [
        migrations.AddField(
            model_name='user_keys',
            name='owned_by_enterprise',
            field=models.NullBooleanField(default=None),
        ),
        migrations.RunSQL("update mfa_user_keys set owned_by_enterprise = %s where key_type='FIDO2'"%(1 if getattr(settings,"MFA_OWNED_BY_ENTERPRISE",False) else 0 ))
    ]
