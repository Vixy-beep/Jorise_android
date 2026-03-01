"""
Jorise v2 - Módulo de Entrenamiento con PCAP y CSV
Modelos para gestionar datasets, jobs y modelos entrenados
"""

from django.db import models
from django.contrib.auth.models import User
import uuid


class TrainingDataset(models.Model):
    """Dataset cargado por el usuario (PCAP o CSV)"""
    FILE_TYPE_CHOICES = [
        ('pcap', 'PCAP - Captura de tráfico de red'),
        ('csv',  'CSV - Dataset etiquetado'),
    ]
    STATUS_CHOICES = [
        ('uploaded',   'Subido'),
        ('processing', 'Procesando'),
        ('ready',      'Listo'),
        ('error',      'Error'),
    ]

    id          = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user        = models.ForeignKey(User, on_delete=models.CASCADE, related_name='datasets')
    name        = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    file_type   = models.CharField(max_length=10, choices=FILE_TYPE_CHOICES)
    file        = models.FileField(upload_to='training/datasets/')
    file_size   = models.BigIntegerField(default=0)
    status      = models.CharField(max_length=20, choices=STATUS_CHOICES, default='uploaded')
    error_msg   = models.TextField(blank=True)

    # Estadísticas tras el procesado
    total_samples   = models.IntegerField(default=0)
    normal_samples  = models.IntegerField(default=0)
    attack_samples  = models.IntegerField(default=0)
    feature_count   = models.IntegerField(default=0)
    label_column    = models.CharField(max_length=100, blank=True)   # sólo CSV
    columns_json    = models.JSONField(default=list, blank=True)     # columnas detectadas

    created_at  = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        db_table = 'training_datasets'

    def __str__(self):
        return f"{self.name} ({self.file_type.upper()})"


class TrainingJob(models.Model):
    """Job de entrenamiento de un modelo ML"""
    ALGORITHM_CHOICES = [
        ('random_forest',    'Random Forest'),
        ('gradient_boost',   'Gradient Boosting'),
        ('isolation_forest', 'Isolation Forest (Anomalías)'),
        ('svm',              'SVM'),
        ('logistic',         'Regresión Logística'),
        ('neural_net',       'Red Neuronal (MLP)'),
    ]
    STATUS_CHOICES = [
        ('pending',   'Pendiente'),
        ('running',   'Entrenando'),
        ('done',      'Completado'),
        ('failed',    'Fallido'),
    ]

    id          = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user        = models.ForeignKey(User, on_delete=models.CASCADE, related_name='training_jobs')
    dataset     = models.ForeignKey(TrainingDataset, on_delete=models.CASCADE, related_name='jobs')
    model_name  = models.CharField(max_length=200)
    algorithm   = models.CharField(max_length=30, choices=ALGORITHM_CHOICES, default='random_forest')
    status      = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    hyperparams = models.JSONField(default=dict, blank=True)

    # Resultados
    accuracy    = models.FloatField(null=True, blank=True)
    precision   = models.FloatField(null=True, blank=True)
    recall      = models.FloatField(null=True, blank=True)
    f1_score    = models.FloatField(null=True, blank=True)
    report_json = models.JSONField(default=dict, blank=True)
    error_msg   = models.TextField(blank=True)

    started_at  = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at  = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        db_table = 'training_jobs'

    def __str__(self):
        return f"{self.model_name} [{self.algorithm}] - {self.status}"


class TrainedModel(models.Model):
    """Modelo ML entrenado listo para usar en Jorise"""
    MODULE_CHOICES = [
        ('siem',    'SIEM - Detección de eventos'),
        ('edr',     'EDR - Detección de procesos'),
        ('waf',     'WAF - Tráfico web'),
        ('network', 'Red - Anomalías de red'),
        ('general', 'General'),
    ]

    id           = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    job          = models.OneToOneField(TrainingJob, on_delete=models.CASCADE, related_name='trained_model')
    name         = models.CharField(max_length=200)
    module       = models.CharField(max_length=20, choices=MODULE_CHOICES, default='general')
    model_file   = models.FileField(upload_to='training/models/')
    scaler_file  = models.FileField(upload_to='training/scalers/', null=True, blank=True)
    features_json = models.JSONField(default=list)   # lista de features usadas
    is_active    = models.BooleanField(default=True)
    predictions  = models.IntegerField(default=0)    # veces usado

    created_at   = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        db_table = 'trained_models'

    def __str__(self):
        return f"{self.name} ({self.module})"
