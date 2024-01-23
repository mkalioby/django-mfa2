# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):
    dependencies = [
        ("mfa", "0002_user_keys_key_type"),
    ]

    operations = [
        migrations.AlterField(
            model_name="user_keys",
            name="secret_key",
            field=models.CharField(max_length=32),
        ),
    ]
