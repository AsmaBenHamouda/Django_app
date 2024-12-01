from django.contrib import admin
from .models import *
from django.contrib.auth.admin import UserAdmin
# Register your models here.
admin.site.unregister(User)
admin.site.register(User, UserAdmin)
admin.site.register(PasswordReset)
@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ('name', 'sku', 'price', 'quantity', 'supplier', 'display_encrypted_bank_number')

    def display_encrypted_bank_number(self, obj):
        return obj.display_encrypted_bank_number()

    display_encrypted_bank_number.short_description = "Encrypted Bank Number"

    