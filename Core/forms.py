from django import forms
from .models import Product
from captcha.fields import CaptchaField

class ProductForm(forms.ModelForm):
    ENCRYPTION_CHOICES = Product.ENCRYPTION_CHOICES
    encryption_type = forms.ChoiceField(
        choices=ENCRYPTION_CHOICES,
        widget=forms.Select(attrs={'class': 'form-control'}),
        label='Encryption Type'
    )
    bank_number = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Bank Number', 'class': 'form-control'}),
        required=False
    )
    captcha = CaptchaField(label='Security Controle')
    
    class Meta:
        model = Product
        exclude = ('created_by',)
        fields = '__all__'
        labels = {
            'product_id': 'Product ID',
            'name': 'Name',
            'sku': 'SKU',
            'price': 'Price',
            'quantity': 'Quantity',
            'supplier': 'Supplier',
            'bank_number': 'Bank Number',
        }
        widgets = {
            'product_id': forms.NumberInput(
                attrs={'placeholder':'e.g. 1', 'class':'form-control'}),
            'name': forms.TextInput(
                attrs={'placeholder':'e.g. shirt', 'class':'form-control'}),
            'sku': forms.TextInput(
                attrs={'placeholder':'e.g. S12345', 'class':'form-control'}),
            'price': forms.NumberInput(
                attrs={'placeholder':'e.g. 19.99', 'class':'form-control'}),
            'quantity': forms.NumberInput(
                attrs={'placeholder':'e.g. 10', 'class':'form-control'}),
            'supplier': forms.TextInput(
                attrs={'placeholder':'e.g. ABC Corp', 'class':'form-control'}),
        }
    def save(self, commit=True):
        """Override the save method to handle encryption of the bank number."""
        product = super().save(commit=False)  # Create an instance without saving it yet
        raw_bank_number = self.cleaned_data.get('bank_number') 
        encryption_type = self.cleaned_data.get('encryption_type') # Get raw input
        if raw_bank_number:
            if encryption_type == 'fernet':
                product.set_bank_number(raw_bank_number)
            elif encryption_type == 'caesar':
                product.bank_number = self.encrypt_caesar(raw_bank_number)
            elif encryption_type.startswith('aes'):
                try:
                    key_size = int(encryption_type[3:])
                    product.bank_number = self.encrypt_aes(raw_bank_number, key_size)
                except ValueError:
                    raise ValueError(f"Invalid AES key size: {encryption_type}")

        product.encryption_type = encryption_type
        if commit:
            product.save()  # Save the instance to the database
        return product
    def encrypt_caesar(self, text, shift=3):
        """Encrypt using Caesar cipher."""
        encrypted = ''.join(
            chr((ord(char) - 65 + shift) % 26 + 65) if char.isupper() else
            chr((ord(char) - 97 + shift) % 26 + 97) if char.islower() else char
            for char in text
        )
        return encrypted.encode()

    def encrypt_aes(self, text, key_size):
        """Encrypt using AES with the specified key size."""
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        key_size_map = {
            128: 16,  # AES 128
            192: 24,  # AES 192
            256: 32   # AES 256
        }
        # Get the correct key size in bytes
        if key_size not in key_size_map:
            raise ValueError(f"Invalid AES key size: {key_size}")
        
         # AES key in bytes
        key = b'ASMAASMAASMAASMA'[:key_size_map[key_size]]  # Ensure correct key size
        cipher = AES.new(key, AES.MODE_ECB)
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pad(text.encode(), AES.block_size))