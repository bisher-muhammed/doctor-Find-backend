# Generated by Django 4.2.5 on 2024-08-08 11:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Users', '0006_alter_myuser_is_active'),
    ]

    operations = [
        migrations.AddField(
            model_name='myuser',
            name='user_type',
            field=models.CharField(choices=[('admin', 'Admin'), ('patient', 'Patient'), ('doctor', 'Doctor')], default='patient', max_length=10),
        ),
    ]
