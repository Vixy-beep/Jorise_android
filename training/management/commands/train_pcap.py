"""
Management command: train_pcap / train_csv

Uso:
    python manage.py train_pcap --file Wednesday-WorkingHours.pcap --name "Miércoles Laboral"
    python manage.py train_pcap --file dataset.csv --algorithm random_forest
"""

import os
import sys
import logging

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model

logger = logging.getLogger(__name__)
User = get_user_model()


class Command(BaseCommand):
    help = 'Entrena un modelo Jorise a partir de un archivo PCAP o CSV'

    def add_arguments(self, parser):
        parser.add_argument(
            '--file', required=True,
            help='Ruta al archivo .pcap o .csv (puede ser relativa al directorio actual)',
        )
        parser.add_argument(
            '--name', default='',
            help='Nombre del dataset / modelo (default: nombre del archivo)',
        )
        parser.add_argument(
            '--algorithm', default='',
            help=(
                'Algoritmo ML: random_forest, gradient_boost, isolation_forest, '
                'svm, logistic, neural_net  (default: isolation_forest para PCAP, '
                'random_forest para CSV)'
            ),
        )
        parser.add_argument(
            '--username', default='',
            help='Nombre de usuario Django para asignar el job (default: primer superusuario)',
        )
        parser.add_argument(
            '--description', default='',
            help='Descripción del dataset',
        )

    def handle(self, *args, **options):
        file_path   = options['file']
        name        = options['name']
        algorithm   = options['algorithm']
        username    = options['username']
        description = options['description']

        # ── Resolver ruta absoluta ──
        if not os.path.isabs(file_path):
            file_path = os.path.join(os.getcwd(), file_path)

        if not os.path.exists(file_path):
            raise CommandError(f'Archivo no encontrado: {file_path}')

        ext = os.path.splitext(file_path)[1].lstrip('.').lower()
        if ext not in ('pcap', 'csv'):
            raise CommandError(f'Extensión no soportada: .{ext}  (usa .pcap o .csv)')

        if not name:
            name = os.path.splitext(os.path.basename(file_path))[0]

        if not algorithm:
            algorithm = 'isolation_forest' if ext == 'pcap' else 'random_forest'

        # ── Obtener usuario ──
        if username:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                raise CommandError(f'Usuario no encontrado: {username}')
        else:
            user = User.objects.filter(is_superuser=True).first()
            if not user:
                user = User.objects.first()
            if not user:
                raise CommandError('No hay usuarios en la base de datos. Crea uno con createsuperuser.')

        self.stdout.write(f'Usuario: {user.username}')
        self.stdout.write(f'Archivo: {file_path}  ({ext.upper()})')
        self.stdout.write(f'Algoritmo: {algorithm}')

        # ── Importar modelos ──
        from training.models import TrainingDataset, TrainingJob
        from django.core.files import File

        # Crear dataset
        with open(file_path, 'rb') as fobj:
            ds = TrainingDataset(
                user        = user,
                name        = name,
                description = description,
                file_type   = ext,
                file_size   = os.path.getsize(file_path),
                status      = 'processing',
            )
            ds.file.save(os.path.basename(file_path), File(fobj), save=False)
            ds.save()

        self.stdout.write(f'Dataset creado: {ds.pk}')

        # Crear job
        job = TrainingJob.objects.create(
            user       = user,
            dataset    = ds,
            model_name = name,
            algorithm  = algorithm,
            status     = 'pending',
        )

        self.stdout.write(self.style.WARNING(f'Iniciando entrenamiento (job: {job.pk})…'))

        # Ejecutar en el mismo hilo para ver el output en consola
        def _progress(msg):
            self.stdout.write(f'  → {msg}')

        try:
            from training.ml_engine import train_from_pcap, train_from_csv
            from training.models import TrainedModel
            from django.core.files.base import ContentFile
            from datetime import datetime, timezone

            if ext == 'pcap':
                result = train_from_pcap(str(job.pk), ds.file.path, algorithm, {}, _progress)
            else:
                result = train_from_csv(str(job.pk), ds.file.path, algorithm, {}, progress_callback=_progress)

            # Actualizar dataset
            ds.total_samples  = result['n_samples']
            ds.normal_samples = result.get('n_normal', 0)
            ds.attack_samples = result.get('n_attack', 0)
            ds.feature_count  = len(result['features'])
            ds.label_column   = result.get('label_col', '')
            ds.columns_json   = result.get('columns', result['features'])
            ds.status = 'ready'
            ds.save()

            # Actualizar job
            m = result['metrics']
            job.accuracy    = m.get('accuracy')
            job.precision   = m.get('precision')
            job.recall      = m.get('recall')
            job.f1_score    = m.get('f1')
            job.report_json = m
            job.status      = 'done'
            job.finished_at = datetime.now(timezone.utc)
            job.save()

            # Guardar modelo
            tm = TrainedModel(
                job=job,
                name=name,
                module='network',
                features_json=result['features'],
            )
            tm.model_file.save(f'{job.pk}_model.pkl',  ContentFile(result['model_bytes']),  save=False)
            tm.scaler_file.save(f'{job.pk}_scaler.pkl', ContentFile(result['scaler_bytes']), save=False)
            tm.save()

            self.stdout.write(self.style.SUCCESS(
                f'\n✅  Entrenamiento completado!'
            ))
            self.stdout.write(f'   Flujos/muestras : {result["n_samples"]:,}')
            self.stdout.write(f'   Normales        : {result.get("n_normal", "—") }')
            self.stdout.write(f'   Anomalías/ataques: {result.get("n_attack", "—")}')
            if m.get('accuracy') is not None:
                self.stdout.write(f'   Accuracy        : {m["accuracy"]:.4f}')
                self.stdout.write(f'   F1 Score        : {m["f1"]:.4f}')
            self.stdout.write(f'   Modelo guardado : {tm.pk}')

        except Exception as exc:
            job.status    = 'failed'
            job.error_msg = str(exc)
            job.save()
            ds.status    = 'error'
            ds.error_msg = str(exc)
            ds.save()
            raise CommandError(f'Entrenamiento fallido: {exc}') from exc
