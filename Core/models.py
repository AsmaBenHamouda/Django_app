from django.db import models
from django.contrib.auth.models import User
import uuid
from cryptography.fernet import Fernet
from django.conf import settings



# Create your models here.
class PasswordReset(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    reset_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    created_when = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Password reset for {self.user.username} at {self.created_when}"

class Product(models.Model):
    product_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    sku = models.CharField(max_length=50, unique = True)
    price = models.FloatField()
    quantity = models.IntegerField()
    supplier = models.CharField(max_length=100)
    bank_number = models.BinaryField()
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