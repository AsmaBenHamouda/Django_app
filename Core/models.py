from django.db import models
from django.contrib.auth.models import User
import uuid
from cryptography.fernet import Fernet
from django.conf import settings
from .models import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes




# Create your models here.

class PasswordReset(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    reset_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    created_when = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Password reset for {self.user.username} at {self.created_when}"

class Product(models.Model):
    ENCRYPTION_CHOICES = [
        ('fernet', 'Fernet'),
        ('caesar', 'Caesar'),
        ('aes192', 'AES 192'),
        ('aes128', 'AES 128'),
        ('aes256', 'AES 256'),
    ]
    product_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    sku = models.CharField(max_length=50, unique = True)
    price = models.FloatField()
    quantity = models.IntegerField()
    supplier = models.CharField(max_length=100)
    bank_number = models.BinaryField()
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    encryption_type = models.CharField(
        max_length=10,
        choices=ENCRYPTION_CHOICES,
        default='fernet'
    )
    

    
    class Meta:
        permissions = [
            ("can_create_product", "Can create product"),
            ("can_update_product", "Can update product"),
            ("can_delete_product", "Can delete product"),
            ('can_view_product', 'Can view product'),
            ("can_view_own_products", "Can view own products"),
            ("can_view_all_products", "Can view all products"),
            ("can_view_product_keys", "Can view and update encryption keys"),
            
        ]
    def __str__(self):
        return self.name
    

    def set_bank_number(self, raw_number):
        """Encrypt and set the bank number."""
        fernet = Fernet(settings.FERNET_KEY)
        self.bank_number = fernet.encrypt(raw_number.encode())
    
    

    def get_bank_number(self):
        """Decrypt and get the bank number."""
        if self.bank_number:
            fernet = Fernet(settings.FERNET_KEY)
            return fernet.decrypt(self.bank_number).decode()
        return None

    def display_encrypted_bank_number(self):
        """Display the encrypted bank number (hexadecimal or Base64 for readability)."""
        if self.bank_number:
            return self.bank_number.hex()  # Or use Base64 for cleaner output.

class EncryptedKey(models.Model):
    key_type = models.CharField(max_length=50, unique=True)
    encrypted_key = models.TextField()