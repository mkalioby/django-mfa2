# Generated by Django 2.0 on 2020-11-10 05:57

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("mfa", "0009_user_keys_owned_by_enterprise"),
    ]

    operations = [
        migrations.AlterField(
            model_name="user_keys",
            name="key_type",
            field=models.CharField(default="TOTP", max_length=25),
        ),
    ]
