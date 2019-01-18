# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('mfa', '0006_trusted_devices'),
    ]

    operations = [
        migrations.DeleteModel(
            name='Trusted_Devices',
        ),
        migrations.AddField(
            model_name='user_keys',
            name='expires',
            field=models.DateTimeField(default=None, null=True, blank=True),
        ),
    ]
