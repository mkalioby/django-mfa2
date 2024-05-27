# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):
    dependencies = [
        ("mfa", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="user_keys",
            name="key_type",
            field=models.CharField(default=b"TOTP", max_length=25),
        ),
    ]
