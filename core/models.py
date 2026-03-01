"""
Jorise v2 - Enterprise Security Operations Center
Core Models - Base de datos central para todos los módulos de seguridad
"""

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
import uuid

# Import user profile
from .user_models import UserProfile


class Organization(models.Model):
    """Organización cliente del SaaS"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    domain = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return self.name


class Subscription(models.Model):
    """Plan de suscripción SaaS"""
    PLAN_CHOICES = [
        ('free', 'Free'),
        ('pro', 'Professional'),
        ('enterprise', 'Enterprise'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('cancelled', 'Cancelled'),
        ('expired', 'Expired'),
        ('trialing', 'Trialing'),
    ]
    
    organization = models.OneToOneField(Organization, on_delete=models.CASCADE, related_name='subscription')
    plan = models.CharField(max_length=20, choices=PLAN_CHOICES, default='free')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='trialing')
    stripe_subscription_id = models.CharField(max_length=100, null=True, blank=True)
    
    # Límites por plan
    max_events_per_month = models.IntegerField(default=1000)
    max_endpoints = models.IntegerField(default=5)
    max_api_calls_per_day = models.IntegerField(default=100)
    
    # Características habilitadas
    siem_enabled = models.BooleanField(default=False)
    edr_enabled = models.BooleanField(default=False)
    waf_enabled = models.BooleanField(default=False)
    antivirus_enabled = models.BooleanField(default=True)
    sandbox_enabled = models.BooleanField(default=True)
    ai_analysis_enabled = models.BooleanField(default=False)
    
    trial_ends_at = models.DateTimeField(null=True, blank=True)
    current_period_start = models.DateTimeField(default=timezone.now)
    current_period_end = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.organization.name} - {self.get_plan_display()}"
    
    def is_feature_enabled(self, feature):
        """Verifica si una característica está habilitada"""
        return getattr(self, f'{feature}_enabled', False)


class APIKey(models.Model):
    """API Keys para acceso programático"""
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='api_keys')
    name = models.CharField(max_length=100)
    key = models.CharField(max_length=100, unique=True, default=uuid.uuid4)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)
    last_used = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.organization.name} - {self.name}"


class SecurityEvent(models.Model):
    """Evento de seguridad detectado por cualquier módulo"""
    SEVERITY_CHOICES = [
        ('info', 'Info'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    MODULE_CHOICES = [
        ('siem', 'SIEM'),
        ('edr', 'EDR'),
        ('waf', 'WAF'),
        ('antivirus', 'Antivirus'),
        ('sandbox', 'Sandbox'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='events')
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    module = models.CharField(max_length=20, choices=MODULE_CHOICES, db_index=True)
    event_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, db_index=True)
    
    # Información de red
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    source_port = models.IntegerField(null=True, blank=True)
    target_ip = models.GenericIPAddressField(null=True, blank=True)
    target_port = models.IntegerField(null=True, blank=True)

    # Geolocalización (se rellena automáticamente al guardar)
    source_country = models.CharField(max_length=100, null=True, blank=True)
    source_city = models.CharField(max_length=100, null=True, blank=True)
    source_lat = models.FloatField(null=True, blank=True)
    source_lon = models.FloatField(null=True, blank=True)
    
    # Detalles
    title = models.CharField(max_length=200)
    description = models.TextField()
    raw_data = models.JSONField(default=dict)
    
    # Análisis IA
    ai_analysis = models.TextField(null=True, blank=True)
    ai_confidence = models.FloatField(null=True, blank=True, validators=[MinValueValidator(0), MaxValueValidator(1)])
    anomaly_score = models.FloatField(null=True, blank=True, validators=[MinValueValidator(0), MaxValueValidator(1)])
    
    # Estado
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='resolved_events')
    
    # Respuesta automatizada
    action_taken = models.CharField(max_length=50, null=True, blank=True)
    action_details = models.JSONField(null=True, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp', 'severity']),
            models.Index(fields=['module', 'is_resolved']),
            models.Index(fields=['organization', '-timestamp']),
        ]
    
    def __str__(self):
        return f"[{self.get_severity_display()}] {self.title}"


class ThreatIntelligence(models.Model):
    """Base de datos de amenazas conocidas (IOCs)"""
    IOC_TYPE_CHOICES = [
        ('ip', 'IP Address'),
        ('domain', 'Domain'),
        ('url', 'URL'),
        ('hash_md5', 'MD5 Hash'),
        ('hash_sha1', 'SHA1 Hash'),
        ('hash_sha256', 'SHA256 Hash'),
        ('email', 'Email'),
        ('cve', 'CVE'),
    ]
    
    THREAT_LEVEL_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    ioc_type = models.CharField(max_length=20, choices=IOC_TYPE_CHOICES, db_index=True)
    ioc_value = models.CharField(max_length=500, db_index=True)
    threat_level = models.CharField(max_length=20, choices=THREAT_LEVEL_CHOICES)
    description = models.TextField()
    source = models.CharField(max_length=100)  # VirusTotal, AlienVault, etc.
    
    # Metadatos
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    times_seen = models.IntegerField(default=1)
    
    # IA enrichment
    ai_enrichment = models.JSONField(null=True, blank=True)
    tags = models.JSONField(default=list)
    
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['ioc_type', 'ioc_value']
        indexes = [
            models.Index(fields=['ioc_type', 'ioc_value']),
            models.Index(fields=['threat_level']),
        ]
    
    def __str__(self):
        return f"{self.get_ioc_type_display()}: {self.ioc_value}"


class SIEMLog(models.Model):
    """Logs recolectados de diferentes fuentes para análisis SIEM"""
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='siem_logs')
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    
    # Fuente del log
    source = models.CharField(max_length=100)  # Servidor, Firewall, App, etc.
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    log_level = models.CharField(max_length=20)  # INFO, WARNING, ERROR, CRITICAL
    
    # Contenido
    message = models.TextField()
    raw_log = models.TextField()
    parsed_data = models.JSONField(default=dict)
    
    # Análisis IA
    ai_classified = models.BooleanField(default=False)
    anomaly_score = models.FloatField(null=True, blank=True, validators=[MinValueValidator(0), MaxValueValidator(1)])
    threat_detected = models.BooleanField(default=False)
    
    # Relación con eventos
    related_event = models.ForeignKey(SecurityEvent, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['organization', '-timestamp']),
            models.Index(fields=['threat_detected', '-timestamp']),
        ]


class EDRAgent(models.Model):
    """Agentes EDR instalados en endpoints"""
    STATUS_CHOICES = [
        ('online', 'Online'),
        ('offline', 'Offline'),
        ('error', 'Error'),
    ]
    
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='edr_agents')
    agent_id = models.UUIDField(default=uuid.uuid4, unique=True)
    hostname = models.CharField(max_length=200)
    ip_address = models.GenericIPAddressField()
    
    # Sistema
    os_type = models.CharField(max_length=50)  # Windows, Linux, MacOS
    os_version = models.CharField(max_length=100)
    
    # Estado
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='offline')
    last_seen = models.DateTimeField(default=timezone.now)
    
    # Versión del agente
    agent_version = models.CharField(max_length=20)
    
    # Configuración
    config = models.JSONField(default=dict)
    
    installed_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['organization', 'hostname']
    
    def __str__(self):
        return f"{self.hostname} ({self.ip_address})"


class EDRProcess(models.Model):
    """Procesos detectados por EDR"""
    agent = models.ForeignKey(EDRAgent, on_delete=models.CASCADE, related_name='processes')
    timestamp = models.DateTimeField(default=timezone.now)
    
    process_name = models.CharField(max_length=200)
    process_id = models.IntegerField()
    parent_process_id = models.IntegerField(null=True)
    command_line = models.TextField()
    user = models.CharField(max_length=100)
    
    # Hash del ejecutable
    file_hash = models.CharField(max_length=64, null=True, blank=True)
    file_path = models.TextField()
    
    # Análisis IA
    is_suspicious = models.BooleanField(default=False)
    threat_score = models.FloatField(null=True, blank=True, validators=[MinValueValidator(0), MaxValueValidator(1)])
    ai_verdict = models.CharField(max_length=50, null=True, blank=True)
    
    # Acción tomada
    blocked = models.BooleanField(default=False)
    action_taken = models.CharField(max_length=50, null=True, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['agent', '-timestamp']),
            models.Index(fields=['is_suspicious', '-timestamp']),
        ]


class WAFRule(models.Model):
    """Reglas del Web Application Firewall"""
    RULE_TYPE_CHOICES = [
        ('sql_injection', 'SQL Injection'),
        ('xss', 'Cross-Site Scripting'),
        ('lfi', 'Local File Inclusion'),
        ('rfi', 'Remote File Inclusion'),
        ('command_injection', 'Command Injection'),
        ('rate_limit', 'Rate Limiting'),
        ('geo_block', 'Geo Blocking'),
        ('custom', 'Custom Rule'),
    ]
    
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='waf_rules')
    name = models.CharField(max_length=200)
    description = models.TextField()
    rule_type = models.CharField(max_length=30, choices=RULE_TYPE_CHOICES)
    
    # Patrón de detección
    pattern = models.TextField()  # Regex o pattern
    severity = models.CharField(max_length=20, choices=SecurityEvent.SEVERITY_CHOICES)
    
    # Acción
    action = models.CharField(max_length=20, choices=[
        ('block', 'Block'),
        ('alert', 'Alert Only'),
        ('challenge', 'Challenge'),
    ], default='alert')
    
    # Estado
    is_enabled = models.BooleanField(default=True)
    is_ai_generated = models.BooleanField(default=False)  # Generada por IA
    
    # Estadísticas
    times_triggered = models.IntegerField(default=0)
    last_triggered = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} ({self.get_rule_type_display()})"


class WAFLog(models.Model):
    """Logs de peticiones HTTP analizadas por WAF"""
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='waf_logs')
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    
    # Request info
    method = models.CharField(max_length=10)
    url = models.TextField()
    headers = models.JSONField(default=dict)
    body = models.TextField(blank=True)
    
    # Cliente
    source_ip = models.GenericIPAddressField()
    user_agent = models.TextField()
    
    # Análisis
    blocked = models.BooleanField(default=False)
    rules_triggered = models.JSONField(default=list)
    threat_score = models.FloatField(validators=[MinValueValidator(0), MaxValueValidator(1)])
    ai_analysis = models.TextField(null=True, blank=True)
    
    # Respuesta
    action_taken = models.CharField(max_length=20)
    response_code = models.IntegerField(null=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['organization', '-timestamp']),
            models.Index(fields=['blocked', '-timestamp']),
        ]


class SandboxAnalysis(models.Model):
    """Análisis de archivos en sandbox"""
    STATUS_CHOICES = [
        ('queued', 'Queued'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    VERDICT_CHOICES = [
        ('clean', 'Clean'),
        ('suspicious', 'Suspicious'),
        ('malicious', 'Malicious'),
    ]
    
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='sandbox_analyses')
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Archivo
    file_name = models.CharField(max_length=255)
    file_size = models.BigIntegerField()
    file_hash_md5 = models.CharField(max_length=32, db_index=True)
    file_hash_sha256 = models.CharField(max_length=64, db_index=True)
    file_path = models.CharField(max_length=500)
    
    # Ejecución
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='queued')
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Resultados
    verdict = models.CharField(max_length=20, choices=VERDICT_CHOICES, null=True, blank=True)
    threat_score = models.FloatField(null=True, blank=True, validators=[MinValueValidator(0), MaxValueValidator(100)])
    
    # Comportamiento detectado
    network_activity = models.JSONField(default=dict)
    file_operations = models.JSONField(default=list)
    registry_operations = models.JSONField(default=list)
    processes_created = models.JSONField(default=list)
    
    # VirusTotal
    virustotal_detections = models.IntegerField(null=True, blank=True)
    virustotal_total = models.IntegerField(null=True, blank=True)
    virustotal_data = models.JSONField(null=True, blank=True)
    
    # Análisis IA
    ai_report = models.TextField(null=True, blank=True)
    ai_recommendations = models.JSONField(default=list)
    
    # Usuario
    submitted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    created_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['organization', '-created_at']),
            models.Index(fields=['status', '-created_at']),
        ]
    
    def __str__(self):
        return f"{self.file_name} - {self.get_verdict_display()}"


class UsageMetrics(models.Model):
    """Métricas de uso para billing y límites"""
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='usage_metrics')
    date = models.DateField(default=timezone.now)
    
    # Contadores
    events_count = models.IntegerField(default=0)
    api_calls_count = models.IntegerField(default=0)
    scans_count = models.IntegerField(default=0)
    logs_ingested = models.BigIntegerField(default=0)
    
    created_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        unique_together = ['organization', 'date']
        ordering = ['-date']
