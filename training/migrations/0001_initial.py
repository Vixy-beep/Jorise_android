# Generated migration for training app
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='TrainingDataset',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=200)),
                ('description', models.TextField(blank=True)),
                ('file_type', models.CharField(choices=[('pcap', 'PCAP - Captura de tráfico de red'), ('csv', 'CSV - Dataset etiquetado')], max_length=10)),
                ('file', models.FileField(upload_to='training/datasets/')),
                ('file_size', models.BigIntegerField(default=0)),
                ('status', models.CharField(choices=[('uploaded', 'Subido'), ('processing', 'Procesando'), ('ready', 'Listo'), ('error', 'Error')], default='uploaded', max_length=20)),
                ('error_msg', models.TextField(blank=True)),
                ('total_samples', models.IntegerField(default=0)),
                ('normal_samples', models.IntegerField(default=0)),
                ('attack_samples', models.IntegerField(default=0)),
                ('feature_count', models.IntegerField(default=0)),
                ('label_column', models.CharField(blank=True, max_length=100)),
                ('columns_json', models.JSONField(blank=True, default=list)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='datasets', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-created_at'], 'db_table': 'training_datasets'},
        ),
        migrations.CreateModel(
            name='TrainingJob',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('model_name', models.CharField(max_length=200)),
                ('algorithm', models.CharField(choices=[('random_forest', 'Random Forest'), ('gradient_boost', 'Gradient Boosting'), ('isolation_forest', 'Isolation Forest (Anomalías)'), ('svm', 'SVM'), ('logistic', 'Regresión Logística'), ('neural_net', 'Red Neuronal (MLP)')], default='random_forest', max_length=30)),
                ('status', models.CharField(choices=[('pending', 'Pendiente'), ('running', 'Entrenando'), ('done', 'Completado'), ('failed', 'Fallido')], default='pending', max_length=20)),
                ('hyperparams', models.JSONField(blank=True, default=dict)),
                ('accuracy', models.FloatField(blank=True, null=True)),
                ('precision', models.FloatField(blank=True, null=True)),
                ('recall', models.FloatField(blank=True, null=True)),
                ('f1_score', models.FloatField(blank=True, null=True)),
                ('report_json', models.JSONField(blank=True, default=dict)),
                ('error_msg', models.TextField(blank=True)),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('finished_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('dataset', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='jobs', to='training.trainingdataset')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='training_jobs', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-created_at'], 'db_table': 'training_jobs'},
        ),
        migrations.CreateModel(
            name='TrainedModel',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=200)),
                ('module', models.CharField(choices=[('siem', 'SIEM - Detección de eventos'), ('edr', 'EDR - Detección de procesos'), ('waf', 'WAF - Tráfico web'), ('network', 'Red - Anomalías de red'), ('general', 'General')], default='general', max_length=20)),
                ('model_file', models.FileField(upload_to='training/models/')),
                ('scaler_file', models.FileField(blank=True, null=True, upload_to='training/scalers/')),
                ('features_json', models.JSONField(default=list)),
                ('is_active', models.BooleanField(default=True)),
                ('predictions', models.IntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('job', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='trained_model', to='training.trainingjob')),
            ],
            options={'ordering': ['-created_at'], 'db_table': 'trained_models'},
        ),
    ]
