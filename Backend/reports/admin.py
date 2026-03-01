from django.contrib import admin
from .models import Report


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ['title', 'report_type', 'format', 'generated_date', 'created_at']
    list_filter = ['report_type', 'format', 'generated_date'] 
    search_fields = ['title']
    
    fieldsets = (
        ('Información del Reporte', {
            'fields': ('title', 'report_type', 'format')
        }),
        ('Contenido', {
            'fields': ('scan_results',)
        }),
        ('Archivo Generado', {
            'fields': ('file_path',)
        }),
        ('Metadatos', {
            'fields': ('generated_date', 'created_at'),
            'classes': ('collapse',)
        })
    )
