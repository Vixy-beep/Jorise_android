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


# ── FASE 3 — Paso 10: Model Versioning ─────────────────────────────────────

class UnifiedModelVersion(models.Model):
    """
    Semantic versioned record of a unified multiclass model.
    Stores full CV metrics, per-class performance, feature discipline results.
    Supports rollback via is_active flag.
    """
    ALGORITHM_CHOICES = [
        ('xgboost',       'XGBoost Multiclass'),
        ('random_forest', 'Random Forest Multiclass'),
    ]
    STATUS_CHOICES = [
        ('training',  'Training'),
        ('evaluating','Evaluating'),
        ('active',    'Active'),
        ('retired',   'Retired'),
        ('failed',    'Failed'),
    ]

    id              = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    version         = models.CharField(max_length=20, unique=True)   # e.g. "1.0.0", "1.1.0"
    algorithm       = models.CharField(max_length=30, choices=ALGORITHM_CHOICES)
    status          = models.CharField(max_length=20, choices=STATUS_CHOICES, default='training')
    is_active       = models.BooleanField(default=False)

    # Training config
    n_splits        = models.IntegerField(default=5)
    sample_per_file = models.IntegerField(default=15000)
    n_samples_total = models.IntegerField(default=0)
    n_features      = models.IntegerField(default=0)
    classes         = models.JSONField(default=list)     # canonical class names
    feature_names   = models.JSONField(default=list)

    # Cross-validation metrics (mean across folds)
    cv_accuracy         = models.FloatField(null=True, blank=True)
    cv_macro_f1         = models.FloatField(null=True, blank=True)
    cv_macro_precision  = models.FloatField(null=True, blank=True)
    cv_macro_recall     = models.FloatField(null=True, blank=True)
    cv_std_f1           = models.FloatField(null=True, blank=True)
    cv_per_class_json   = models.JSONField(default=dict, blank=True)  # {class: {f1, recall, prec}}
    cv_fold_metrics     = models.JSONField(default=list, blank=True)  # per-fold breakdown

    # Feature discipline
    feature_importances = models.JSONField(default=dict, blank=True)  # {feat: importance}
    dominant_features   = models.JSONField(default=list, blank=True)  # top features > 80% importance
    top10_features      = models.JSONField(default=list, blank=True)
    passes_targets      = models.BooleanField(null=True, blank=True)
    weak_classes        = models.JSONField(default=list, blank=True)

    # Cross-domain results (FASE 2 — Paso 5)
    cross_domain_avg_f1    = models.FloatField(null=True, blank=True)
    cross_domain_pass_rate = models.FloatField(null=True, blank=True)
    cross_domain_verdict   = models.CharField(max_length=30, blank=True)
    cross_domain_detail    = models.JSONField(default=dict, blank=True)

    # Anomaly layer metrics
    anomaly_fpr       = models.FloatField(null=True, blank=True)
    anomaly_dr        = models.FloatField(null=True, blank=True)
    anomaly_f1        = models.FloatField(null=True, blank=True)

    # Ensemble weights (FASE 2 — Paso 7)
    ensemble_w_clf     = models.FloatField(default=0.6)
    ensemble_w_anomaly = models.FloatField(default=0.4)
    ensemble_w_context = models.FloatField(default=0.0)

    # File paths
    model_file   = models.CharField(max_length=500, blank=True)
    scaler_file  = models.CharField(max_length=500, blank=True)
    le_file      = models.CharField(max_length=500, blank=True)    # LabelEncoder
    anomaly_file = models.CharField(max_length=500, blank=True)
    ensemble_file= models.CharField(max_length=500, blank=True)

    # Metadata
    notes         = models.TextField(blank=True)
    error_msg     = models.TextField(blank=True)
    training_time = models.FloatField(null=True, blank=True)   # seconds
    created_by    = models.ForeignKey(User, null=True, blank=True,
                                       on_delete=models.SET_NULL, related_name='model_versions')
    created_at    = models.DateTimeField(auto_now_add=True)
    activated_at  = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        db_table  = 'training_unified_versions'

    def __str__(self):
        return f"v{self.version} [{self.algorithm}] {self.status}"

    def activate(self):
        """Set this version as active, retire all others."""
        from django.utils import timezone
        UnifiedModelVersion.objects.filter(is_active=True).update(
            is_active=False, status='retired'
        )
        self.is_active   = True
        self.status      = 'active'
        self.activated_at = timezone.now()
        self.save()

    @classmethod
    def get_active(cls):
        return cls.objects.filter(is_active=True).first()

    @property
    def cv_macro_f1_pct(self):
        return round(self.cv_macro_f1 * 100, 2) if self.cv_macro_f1 else None

    @property
    def verdict_badge(self):
        if self.passes_targets:
            return 'PASS'
        if self.cv_macro_f1 and self.cv_macro_f1 >= 0.65:
            return 'REVIEW'
        return 'FAIL'


# ── FASE 3 — Paso 9: Prediction Audit Log ──────────────────────────────────

class PredictionAudit(models.Model):
    """
    Immutable log of every prediction made by the system.
    Required for enterprise auditability.
    """
    id                 = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp          = models.DateTimeField(auto_now_add=True, db_index=True)

    # Model reference
    model_version      = models.ForeignKey(
        UnifiedModelVersion, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='predictions'
    )
    model_version_str  = models.CharField(max_length=20, blank=True)  # denormalized for speed

    # Input fingerprint (for dedup + traceability, NOT the raw features)
    feature_hash       = models.CharField(max_length=64, db_index=True)  # SHA256 of feature vector
    source_ip          = models.GenericIPAddressField(null=True, blank=True)
    destination_ip     = models.GenericIPAddressField(null=True, blank=True)
    flow_duration_ms   = models.FloatField(null=True, blank=True)

    # Scores
    ensemble_score     = models.FloatField()               # 0..1
    clf_prob_attack    = models.FloatField(null=True)
    anomaly_score      = models.FloatField(null=True)

    # Decision
    predicted_class    = models.CharField(max_length=50)   # canonical label
    is_threat          = models.BooleanField()
    confidence         = models.CharField(max_length=10, blank=True)   # HIGH / MEDIUM / LOW

    # FASE 3 — Paso 8: Explainability (SHAP)
    top_features_json  = models.JSONField(default=list, blank=True)   # [{feature, shap_value}]
    explanation_text   = models.TextField(blank=True)

    # Feedback loop
    analyst_verdict    = models.CharField(max_length=20, blank=True)  # TP / FP / TN / FN
    analyst_notes      = models.TextField(blank=True)
    reviewed_at        = models.DateTimeField(null=True, blank=True)
    reviewed_by        = models.ForeignKey(
        User, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='reviewed_predictions'
    )

    class Meta:
        ordering  = ['-timestamp']
        db_table  = 'training_prediction_audit'
        indexes   = [
            models.Index(fields=['timestamp', 'is_threat']),
            models.Index(fields=['predicted_class']),
            models.Index(fields=['analyst_verdict']),
        ]

    def __str__(self):
        return (f"[{self.timestamp:%Y-%m-%d %H:%M:%S}] "
                f"{self.predicted_class}  score={self.ensemble_score:.3f} "
                f"{'⚠ THREAT' if self.is_threat else 'OK'}")

    @classmethod
    def log(cls, model_version, feature_vector: dict, result: dict,
            source_ip=None, destination_ip=None, flow_duration_ms=None,
            top_features=None, explanation=''):
        """Create an audit log entry. Call this on every prediction."""
        import hashlib, json
        feat_hash = hashlib.sha256(
            json.dumps(feature_vector, sort_keys=True, default=str).encode()
        ).hexdigest()

        score  = float(result.get('ensemble_score', 0))
        conf   = 'HIGH' if score >= 0.80 else ('MEDIUM' if score >= 0.50 else 'LOW')

        return cls.objects.create(
            model_version     = model_version,
            model_version_str = model_version.version if model_version else '',
            feature_hash      = feat_hash,
            source_ip         = source_ip,
            destination_ip    = destination_ip,
            flow_duration_ms  = flow_duration_ms,
            ensemble_score    = score,
            clf_prob_attack   = float(result.get('clf_prob_attack', 0)),
            anomaly_score     = float(result.get('anomaly_score', 0)),
            predicted_class   = str(result.get('clf_class', 'Unknown')),
            is_threat         = bool(result.get('is_threat', False)),
            confidence        = conf,
            top_features_json = top_features or [],
            explanation_text  = explanation,
        )
