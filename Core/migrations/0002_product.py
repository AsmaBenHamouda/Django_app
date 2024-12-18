# Generated by Django 5.1.3 on 2024-11-30 09:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Core', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Product',
            fields=[
                ('product_id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('sku', models.CharField(max_length=50, unique=True)),
                ('price', models.FloatField()),
                ('quantity', models.IntegerField()),
                ('supplier', models.CharField(max_length=100)),
            ],
        ),
    ]
