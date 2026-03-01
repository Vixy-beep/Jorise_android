from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class ScanResult(models.Model):
    """Basic ScanResult model placeholder"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scans')
    target = models.CharField(max_length=500)
    scan_type = models.CharField(max_length=100, default='basic')
    status = models.CharField(max_length=50, default='pending')
    result_data = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        db_table = 'scan_results'
    
    def __str__(self):
        return f"Scan {self.id} - {self.target}"
