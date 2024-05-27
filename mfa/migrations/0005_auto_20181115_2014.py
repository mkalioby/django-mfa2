# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

try:
    from django.db.models import JSONField
except ImportError:
    try:
        from jsonfield.fields import JSONField  # pyre-ignore[21]
    except ImportError:
        raise ImportError(
            "Can't find a JSONField implementation, please install jsonfield if django < 4.0"
        )


def modify_json(apps, schema_editor):
    from django.conf import settings

    if "mysql" in settings.DATABASES.get("default", {}).get("engine", ""):
        migrations.RunSQL("alter table mfa_user_keys modify column properties json;")


class Migration(migrations.Migration):
    dependencies = [
        ("mfa", "0004_user_keys_enabled"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="user_keys",
            name="secret_key",
        ),
        migrations.AddField(
            model_name="user_keys",
            name="properties",
            field=JSONField(null=True),
        ),
        migrations.RunPython(modify_json),
    ]
