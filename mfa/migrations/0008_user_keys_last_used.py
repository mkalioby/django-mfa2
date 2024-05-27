# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):
    dependencies = [
        ("mfa", "0007_auto_20181230_1549"),
    ]

    operations = [
        migrations.AddField(
            model_name="user_keys",
            name="last_used",
            field=models.DateTimeField(default=None, null=True, blank=True),
        ),
    ]
