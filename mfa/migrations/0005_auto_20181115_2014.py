# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import jsonfield.fields


class Migration(migrations.Migration):

    dependencies = [
        ('mfa', '0004_user_keys_enabled'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user_keys',
            name='secret_key',
        ),
        migrations.AddField(
            model_name='user_keys',
            name='properties',
            field=jsonfield.fields.JSONField(null=True),
        ),
        migrations.RunSQL("alter table mfa_user_keys modify column properties json;")
    ]
