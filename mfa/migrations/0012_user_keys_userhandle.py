# Generated by Django 2.2 on 2022-10-16 14:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mfa', '0011_auto_20210530_0622'),
    ]
    operations = [
        migrations.AddField(
            model_name='user_keys',
            name='user_handle',
            field=models.CharField(blank=True, default=None, max_length=255, null=True),
        ),
    ]
