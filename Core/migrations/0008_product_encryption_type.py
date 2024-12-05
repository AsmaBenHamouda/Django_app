# Generated by Django 5.1.3 on 2024-12-05 09:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Core', '0007_alter_product_created_by'),
    ]

    operations = [
        migrations.AddField(
            model_name='product',
            name='encryption_type',
            field=models.CharField(choices=[('fernet', 'Fernet'), ('caesar', 'Caesar'), ('aes64', 'AES 64'), ('aes128', 'AES 128'), ('aes256', 'AES 256')], default='fernet', max_length=10),
        ),
    ]