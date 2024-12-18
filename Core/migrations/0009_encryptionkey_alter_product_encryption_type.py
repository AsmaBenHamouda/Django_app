# Generated by Django 5.1.3 on 2024-12-08 18:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Core', '0008_product_encryption_type'),
    ]

    operations = [
        migrations.CreateModel(
            name='EncryptionKey',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key_type', models.CharField(choices=[('fernet', 'Fernet'), ('caesar', 'Caesar'), ('aes192', 'AES 192'), ('aes128', 'AES 128'), ('aes256', 'AES 256')], max_length=10, unique=True)),
                ('encrypted_key', models.BinaryField()),
                ('last_updated', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.AlterField(
            model_name='product',
            name='encryption_type',
            field=models.CharField(choices=[('fernet', 'Fernet'), ('caesar', 'Caesar'), ('aes192', 'AES 192'), ('aes128', 'AES 128'), ('aes256', 'AES 256')], default='fernet', max_length=10),
        ),
    ]
