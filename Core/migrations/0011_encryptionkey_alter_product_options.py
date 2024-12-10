# Generated by Django 5.1.3 on 2024-12-09 06:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Core', '0010_delete_encryptionkey'),
    ]

    operations = [
        migrations.CreateModel(
            name='EncryptionKey',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key_type', models.CharField(choices=[('aes128', 'AES 128'), ('aes192', 'AES 192'), ('aes256', 'AES 256'), ('fernet', 'Fernet')], max_length=10, unique=True)),
                ('encrypted_key', models.BinaryField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.AlterModelOptions(
            name='product',
            options={'permissions': [('can_create_product', 'Can create product'), ('can_update_product', 'Can update product'), ('can_delete_product', 'Can delete product'), ('can_view_product', 'Can view product'), ('can_view_own_products', 'Can view own products'), ('can_view_all_products', 'Can view all products'), ('view_encryption_key', 'Can view encryption key'), ('add_encryption_key', 'Can add encryption key'), ('change_encryption_key', 'Can change encryption key'), ('delete_encryption_key', 'Can delete encryption key')]},
        ),
    ]
