from django.db import models
from django.utils import timezone


class ScanResult(models.Model):
    SCAN_STATUS_CHOICES = [
        ('pending', 'Pendiente'),
        ('scanning', 'Escaneando'),
        ('completed', 'Completado'),
        ('failed', 'Fallido'),
    ]
    
    THREAT_LEVEL_CHOICES = [
        ('clean', 'Limpio'),
        ('low', 'Bajo'),
        ('medium', 'Medio'),
        ('high', 'Alto'),
        ('critical', 'Crítico'),
    ]
    
    file_name = models.CharField(max_length=255)
    file_hash = models.CharField(max_length=64, unique=True)
    file_size = models.BigIntegerField()
    
    scan_status = models.CharField(max_length=20, choices=SCAN_STATUS_CHOICES, default='pending')
    threat_level = models.CharField(max_length=20, choices=THREAT_LEVEL_CHOICES, default='clean')
    
    engines_detected = models.IntegerField(default=0)
    total_engines = models.IntegerField(default=0)
    
    scan_started = models.DateTimeField(auto_now_add=True)
    scan_completed = models.DateTimeField(null=True, blank=True)
    
    results_json = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['-scan_started']
        
    def __str__(self):
        return f"{self.file_name} - {self.threat_level}"
        
    @property
    def detection_rate(self):
        if self.total_engines > 0:
            return (self.engines_detected / self.total_engines) * 100
        return 0


class ThreatIntelligence(models.Model):
    threat_name = models.CharField(max_length=200)
    threat_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=20)
    
    first_seen = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    
    indicators = models.JSONField(default=list)
    description = models.TextField(blank=True)
    
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.threat_name} ({self.severity})"