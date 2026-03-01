from django.contrib import admin
from .models import ScanResult

@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ['id', 'target', 'scan_type', 'status', 'user', 'created_at']
    list_filter = ['status', 'scan_type', 'created_at']
    search_fields = ['target', 'user__username']
    readonly_fields = ['created_at', 'updated_at']
