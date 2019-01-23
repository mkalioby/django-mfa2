# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import jsonfield.fields


def modify_json(apps, schema_editor):
    from django.conf import settings
    if "mysql" in settings.DATABASES.get("default", {}).get("engine", ""):
        migrations.RunSQL("alter table mfa_user_keys modify column properties json;")


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
        migrations.RunPython(modify_json)
    ]
