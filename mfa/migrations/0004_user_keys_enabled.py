# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('mfa', '0003_auto_20181114_2159'),
    ]

    operations = [
        migrations.AddField(
            model_name='user_keys',
            name='enabled',
            field=models.BooleanField(default=True),
        ),
    ]
