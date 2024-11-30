from django import forms
from .models import Product
from captcha.fields import CaptchaField

class ProductForm(forms.ModelForm):
    bank_number = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Bank Number', 'class': 'form-control'}),
        required=False
    )
    captcha = CaptchaField(label='Security Controle')
    
    class Meta:
        model = Product
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
        raw_bank_number = self.cleaned_data.get('bank_number')  # Get raw input
        if raw_bank_number:  # If a bank number is provided
            product.set_bank_number(raw_bank_number)  # Encrypt it
        if commit:
            product.save()  # Save the instance to the database
        return product