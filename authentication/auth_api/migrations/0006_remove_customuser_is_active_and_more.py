# Generated by Django 5.0.2 on 2024-04-18 18:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_api', '0005_alter_customuser_private_key_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='is_active',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='is_staff',
        ),
        migrations.AlterField(
            model_name='customuser',
            name='password',
            field=models.CharField(max_length=128),
        ),
    ]
