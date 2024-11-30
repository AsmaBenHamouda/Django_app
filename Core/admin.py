from django.contrib import admin
from .models import *

# Register your models here.
admin.site.register(PasswordReset)
@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ('name', 'sku', 'price', 'quantity', 'supplier', 'display_encrypted_bank_number')

    def display_encrypted_bank_number(self, obj):
        return obj.display_encrypted_bank_number()

    display_encrypted_bank_number.short_description = "Encrypted Bank Number"