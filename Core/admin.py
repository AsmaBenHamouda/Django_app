from django.contrib import admin
from .models import *
from django.contrib.auth.admin import UserAdmin
# Register your models here.
admin.site.unregister(User)
admin.site.register(User, UserAdmin)
admin.site.register(PasswordReset)
@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    
    list_display = ('name', 'sku', 'price', 'quantity', 'supplier', 'encryption_type', 'created_by','get_encrypted_bank_number')
    readonly_fields = ('display_encrypted_bank_number',)
    list_filter = ('created_by', 'supplier')
    search_fields = ('name', 'sku')
    
    
    def get_encrypted_bank_number(self, obj):
        """Return the encrypted bank number in a readable format."""
        if obj.bank_number:
            return obj.bank_number.hex()  # Return hex representation of encrypted bank number
        return None  # If no bank number is set, return None
    
    get_encrypted_bank_number.short_description = "Encrypted Bank Number"

    
    def get_queryset(self, request):
        """Customize the queryset to filter products based on permissions."""
        qs = super().get_queryset(request)
        if request.user.has_perm('Core.can_view_all_products'):
            return qs
        return qs.filter(created_by=request.user)  # Only products created by the user

    def save_model(self, request, obj, form, change):
        """Automatically set `created_by` when saving a product."""
        if not obj.created_by:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)
    