# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('mfa', '0005_auto_20181115_2014'),
    ]

    operations = [
        migrations.CreateModel(
            name='Trusted_Devices',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('signature', models.CharField(max_length=255)),
                ('key', models.CharField(max_length=6)),
                ('username', models.CharField(max_length=50)),
                ('user_agent', models.CharField(max_length=255)),
                ('status', models.CharField(default=b'adding', max_length=255)),
                ('added_on', models.DateTimeField(auto_now_add=True)),
                ('last_used', models.DateTimeField(default=None, null=True)),
            ],
        ),
    ]
