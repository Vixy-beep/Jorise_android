from django.db import models
from django.utils import timezone
# LAZY IMPORT: ScanResult se importa en tiempo de ejecución para evitar dependencias circulares


class Report(models.Model):
    REPORT_TYPE_CHOICES = [
        ('individual', 'Individual'),
        ('summary', 'Resumen'),
        ('detailed', 'Detallado'),
    ]
    
    FORMAT_CHOICES = [
        ('html', 'HTML'),
        ('pdf', 'PDF'),
    ]
    
    title = models.CharField(max_length=200)
    report_type = models.CharField(max_length=20, choices=REPORT_TYPE_CHOICES)
    format = models.CharField(max_length=10, choices=FORMAT_CHOICES, default='html')
    
    scan_results = models.ManyToManyField('scan.ScanResult', related_name='reports')
    
    generated_date = models.DateTimeField(default=timezone.now)
    file_path = models.FileField(upload_to='reports/', blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-generated_date']
    
    def __str__(self):
        return f"{self.title} - {self.format.upper()}"
