"""
Jorise v2 - Vistas del módulo de Entrenamiento
Soporta PCAP y CSV.
"""

import os
import json
import logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.http import require_POST
from django.core.paginator import Paginator

from .models import TrainingDataset, TrainingJob, TrainedModel

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {'pcap', 'csv'}
MAX_FILE_SIZE_MB = 500


def _ext(filename: str) -> str:
    return os.path.splitext(filename)[1].lstrip('.').lower()


# ─────────────────────────────────────────────────────────
# Dashboard principal
# ─────────────────────────────────────────────────────────

@login_required
def training_dashboard(request):
    datasets = TrainingDataset.objects.filter(user=request.user).order_by('-created_at')[:10]
    jobs     = TrainingJob.objects.filter(user=request.user).order_by('-created_at')[:10]
    models   = TrainedModel.objects.filter(job__user=request.user).order_by('-created_at')[:10]

    running_jobs = jobs.filter(status__in=['pending', 'running']).count()

    context = {
        'datasets':     datasets,
        'jobs':         jobs,
        'trained_models': models,
        'running_jobs': running_jobs,
        'algorithms': TrainingJob.ALGORITHM_CHOICES,
    }
    return render(request, 'training/dashboard.html', context)


# ─────────────────────────────────────────────────────────
# Subida de dataset (PCAP o CSV)
# ─────────────────────────────────────────────────────────

@login_required
@require_POST
def upload_dataset(request):
    uploaded = request.FILES.get('file')
    name     = request.POST.get('name', '').strip()
    desc     = request.POST.get('description', '').strip()

    if not uploaded:
        messages.error(request, 'Debes seleccionar un archivo.')
        return redirect('training:dashboard')

    ext = _ext(uploaded.name)
    if ext not in ALLOWED_EXTENSIONS:
        messages.error(request, f'Formato no válido: .{ext}. Solo se admiten .pcap y .csv')
        return redirect('training:dashboard')

    size_mb = uploaded.size / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        messages.error(request, f'Archivo demasiado grande ({size_mb:.1f} MB). Máximo {MAX_FILE_SIZE_MB} MB.')
        return redirect('training:dashboard')

    if not name:
        name = os.path.splitext(uploaded.name)[0]

    dataset = TrainingDataset.objects.create(
        user      = request.user,
        name      = name,
        description = desc,
        file_type = ext,
        file      = uploaded,
        file_size = uploaded.size,
        status    = 'uploaded',
    )

    messages.success(request, f'Dataset "{dataset.name}" subido correctamente.')
    return redirect('training:dashboard')


# ─────────────────────────────────────────────────────────
# Lanzar job de entrenamiento
# ─────────────────────────────────────────────────────────

@login_required
@require_POST
def start_training(request):
    dataset_id = request.POST.get('dataset_id')
    model_name = request.POST.get('model_name', '').strip()
    algorithm  = request.POST.get('algorithm', 'random_forest')
    hp_json    = request.POST.get('hyperparams', '{}')

    dataset = get_object_or_404(TrainingDataset, pk=dataset_id, user=request.user)

    if not model_name:
        model_name = f"{dataset.name} - {algorithm}"

    try:
        hyperparams = json.loads(hp_json) if hp_json else {}
    except json.JSONDecodeError:
        hyperparams = {}

    # PCAP siempre usa Isolation Forest
    if dataset.file_type == 'pcap' and algorithm not in ('isolation_forest',):
        messages.info(request, 'Los archivos PCAP usan Isolation Forest automáticamente.')
        algorithm = 'isolation_forest'

    job = TrainingJob.objects.create(
        user       = request.user,
        dataset    = dataset,
        model_name = model_name,
        algorithm  = algorithm,
        hyperparams = hyperparams,
        status     = 'pending',
    )

    # Actualizar dataset
    dataset.status = 'processing'
    dataset.save(update_fields=['status'])

    # Lanzar entrenamiento en hilo
    try:
        from training.ml_engine import start_training_thread
        start_training_thread(str(job.pk))
        messages.success(request, f'Entrenamiento iniciado: "{model_name}"')
    except Exception as e:
        job.status = 'failed'
        job.error_msg = str(e)
        job.save()
        messages.error(request, f'Error al iniciar entrenamiento: {e}')

    return redirect('training:dashboard')


# ─────────────────────────────────────────────────────────
# Estado de un job (API JSON para polling)
# ─────────────────────────────────────────────────────────

@login_required
def job_status(request, job_id):
    job = get_object_or_404(TrainingJob, pk=job_id, user=request.user)
    data = {
        'id':         str(job.pk),
        'status':     job.status,
        'model_name': job.model_name,
        'algorithm':  job.algorithm,
        'accuracy':   job.accuracy,
        'f1_score':   job.f1_score,
        'started_at': str(job.started_at) if job.started_at else None,
        'finished_at': str(job.finished_at) if job.finished_at else None,
        'error_msg':  job.error_msg,
    }
    return JsonResponse(data)


# ─────────────────────────────────────────────────────────
# Detalle de un modelo entrenado
# ─────────────────────────────────────────────────────────

@login_required
def model_detail(request, model_id):
    tm = get_object_or_404(TrainedModel, pk=model_id, job__user=request.user)
    return render(request, 'training/model_detail.html', {'trained_model': tm})


# ─────────────────────────────────────────────────────────
# Eliminar dataset
# ─────────────────────────────────────────────────────────

@login_required
@require_POST
def delete_dataset(request, dataset_id):
    dataset = get_object_or_404(TrainingDataset, pk=dataset_id, user=request.user)
    name = dataset.name
    try:
        if dataset.file and os.path.exists(dataset.file.path):
            os.remove(dataset.file.path)
    except Exception:
        pass
    dataset.delete()
    messages.success(request, f'Dataset "{name}" eliminado.')
    return redirect('training:dashboard')


# ─────────────────────────────────────────────────────────
# Lista todos los datasets (paginada)
# ─────────────────────────────────────────────────────────

@login_required
def dataset_list(request):
    qs = TrainingDataset.objects.filter(user=request.user).order_by('-created_at')
    paginator = Paginator(qs, 20)
    page = paginator.get_page(request.GET.get('page'))
    return render(request, 'training/dataset_list.html', {'page_obj': page})
