# Generated by Django 5.0.2 on 2024-04-26 22:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_api', '0007_alter_customuser_email'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='email',
            field=models.EmailField(max_length=254, unique=True),
        ),
    ]