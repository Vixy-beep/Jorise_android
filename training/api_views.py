"""
Jorise v2 - API REST del módulo de Entrenamiento
Endpoints para consumir modelos entrenados desde cualquier cliente.

Base path: /api/training/

Rutas:
  GET  /api/training/models/                  → lista modelos activos
  GET  /api/training/models/<id>/             → detalle + métricas
  POST /api/training/predict/pcap/            → predice sobre PCAP subido
  POST /api/training/predict/csv/             → predice sobre CSV subido
  GET  /api/training/jobs/                    → lista jobs del usuario
  GET  /api/training/jobs/<id>/               → estado de un job
  POST /api/training/evaluate/                → evalúa modelo contra CSV
"""

import os
import json
import logging
import tempfile

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404

from training.models import TrainedModel, TrainingJob, TrainingDataset

logger = logging.getLogger(__name__)


def _json_error(msg: str, status: int = 400) -> JsonResponse:
    return JsonResponse({'error': msg}, status=status)


def _require_auth(request):
    """Soporta sesión Django o Bearer token JWT."""
    if request.user.is_authenticated:
        return request.user
    # JWT simple: Authorization: Bearer <token>
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        try:
            from rest_framework_simplejwt.tokens import AccessToken
            token   = AccessToken(auth.split(' ', 1)[1])
            from django.contrib.auth import get_user_model
            User    = get_user_model()
            return User.objects.get(pk=token['user_id'])
        except Exception:
            pass
    return None


# ──────────────────────────────────────────────────────────
# GET /api/training/models/
# ──────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(['GET'])
def list_models(request):
    user = _require_auth(request)
    if not user:
        return _json_error('No autenticado.', 401)

    models = TrainedModel.objects.filter(
        job__user=user, is_active=True
    ).select_related('job', 'job__dataset').order_by('-created_at')

    data = []
    for tm in models:
        data.append({
            'id':           str(tm.pk),
            'name':         tm.name,
            'module':       tm.module,
            'algorithm':    tm.job.algorithm,
            'dataset_name': tm.job.dataset.name,
            'dataset_type': tm.job.dataset.file_type,
            'n_features':   len(tm.features_json),
            'predictions':  tm.predictions,
            'accuracy':     tm.job.accuracy,
            'f1_score':     tm.job.f1_score,
            'created_at':   tm.created_at.isoformat(),
        })

    return JsonResponse({'count': len(data), 'models': data})


# ──────────────────────────────────────────────────────────
# GET /api/training/models/<id>/
# ──────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(['GET'])
def model_detail_api(request, model_id):
    user = _require_auth(request)
    if not user:
        return _json_error('No autenticado.', 401)

    tm  = get_object_or_404(TrainedModel, pk=model_id, job__user=user)
    job = tm.job

    return JsonResponse({
        'id':              str(tm.pk),
        'name':            tm.name,
        'module':          tm.module,
        'algorithm':       job.algorithm,
        'features':        tm.features_json,
        'n_features':      len(tm.features_json),
        'predictions':     tm.predictions,
        'is_active':       tm.is_active,
        'created_at':      tm.created_at.isoformat(),
        'dataset': {
            'name':     job.dataset.name,
            'type':     job.dataset.file_type,
            'samples':  job.dataset.total_samples,
            'normal':   job.dataset.normal_samples,
            'attacks':  job.dataset.attack_samples,
        },
        'metrics': {
            'accuracy':  job.accuracy,
            'precision': job.precision,
            'recall':    job.recall,
            'f1_score':  job.f1_score,
            'report':    job.report_json,
        },
    })


# ──────────────────────────────────────────────────────────
# POST /api/training/predict/pcap/
# Body: multipart — model_id, file (.pcap)
# ──────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(['POST'])
def predict_pcap_api(request):
    user = _require_auth(request)
    if not user:
        return _json_error('No autenticado.', 401)

    model_id = request.POST.get('model_id')
    uploaded = request.FILES.get('file')

    if not model_id:
        return _json_error('Falta model_id.')
    if not uploaded:
        return _json_error('Falta el archivo PCAP.')

    ext = os.path.splitext(uploaded.name)[1].lower()
    if ext != '.pcap':
        return _json_error('Solo se aceptan archivos .pcap')

    tm = get_object_or_404(TrainedModel, pk=model_id, job__user=user)

    # Guardar temporalmente
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
        for chunk in uploaded.chunks():
            tmp.write(chunk)
        tmp_path = tmp.name

    try:
        from training.predictor import predict_pcap, get_prediction_summary
        result_df = predict_pcap(tmp_path, tm)
        summary   = get_prediction_summary(result_df)

        # Muestra de los primeros 100 flujos
        sample = result_df[['src_ip', 'dst_ip', 'src_port', 'dst_port',
                              'protocol', 'prediction', 'label', 'confidence']].head(100)

        # Incrementar contador
        tm.predictions += len(result_df)
        tm.save(update_fields=['predictions'])

        return JsonResponse({
            'model_id':    str(tm.pk),
            'model_name':  tm.name,
            'summary':     summary,
            'sample_flows': json.loads(sample.to_json(orient='records')),
        })
    except Exception as e:
        logger.exception(e)
        return _json_error(str(e), 500)
    finally:
        os.unlink(tmp_path)


# ──────────────────────────────────────────────────────────
# POST /api/training/predict/csv/
# Body: multipart — model_id, file (.csv)
# ──────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(['POST'])
def predict_csv_api(request):
    user = _require_auth(request)
    if not user:
        return _json_error('No autenticado.', 401)

    model_id = request.POST.get('model_id')
    uploaded = request.FILES.get('file')

    if not model_id:
        return _json_error('Falta model_id.')
    if not uploaded:
        return _json_error('Falta el archivo CSV.')

    tm = get_object_or_404(TrainedModel, pk=model_id, job__user=user)

    with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as tmp:
        for chunk in uploaded.chunks():
            tmp.write(chunk)
        tmp_path = tmp.name

    try:
        from training.predictor import predict_csv, get_prediction_summary
        result_df = predict_csv(tmp_path, tm)
        summary   = get_prediction_summary(result_df)

        cols = ['prediction', 'label', 'confidence']
        if 'true_label' in result_df.columns:
            cols.append('true_label')
        sample = result_df[cols].head(100)

        tm.predictions += len(result_df)
        tm.save(update_fields=['predictions'])

        return JsonResponse({
            'model_id':     str(tm.pk),
            'model_name':   tm.name,
            'summary':      summary,
            'sample_rows':  json.loads(sample.to_json(orient='records')),
        })
    except Exception as e:
        logger.exception(e)
        return _json_error(str(e), 500)
    finally:
        os.unlink(tmp_path)


# ──────────────────────────────────────────────────────────
# GET /api/training/jobs/
# ──────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(['GET'])
def list_jobs(request):
    user = _require_auth(request)
    if not user:
        return _json_error('No autenticado.', 401)

    jobs = TrainingJob.objects.filter(user=user).select_related('dataset').order_by('-created_at')[:50]

    data = [{
        'id':           str(j.pk),
        'model_name':   j.model_name,
        'algorithm':    j.algorithm,
        'status':       j.status,
        'dataset_name': j.dataset.name,
        'dataset_type': j.dataset.file_type,
        'accuracy':     j.accuracy,
        'f1_score':     j.f1_score,
        'started_at':   j.started_at.isoformat() if j.started_at else None,
        'finished_at':  j.finished_at.isoformat() if j.finished_at else None,
        'error_msg':    j.error_msg or None,
    } for j in jobs]

    return JsonResponse({'count': len(data), 'jobs': data})


# ──────────────────────────────────────────────────────────
# GET /api/training/jobs/<id>/
# ──────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(['GET'])
def job_detail_api(request, job_id):
    user = _require_auth(request)
    if not user:
        return _json_error('No autenticado.', 401)

    job = get_object_or_404(TrainingJob, pk=job_id, user=user)

    data = {
        'id':          str(job.pk),
        'model_name':  job.model_name,
        'algorithm':   job.algorithm,
        'status':      job.status,
        'hyperparams': job.hyperparams,
        'accuracy':    job.accuracy,
        'precision':   job.precision,
        'recall':      job.recall,
        'f1_score':    job.f1_score,
        'report':      job.report_json,
        'error_msg':   job.error_msg or None,
        'started_at':  job.started_at.isoformat() if job.started_at else None,
        'finished_at': job.finished_at.isoformat() if job.finished_at else None,
        'dataset': {
            'id':       str(job.dataset.pk),
            'name':     job.dataset.name,
            'type':     job.dataset.file_type,
            'status':   job.dataset.status,
            'samples':  job.dataset.total_samples,
        },
    }

    # Añadir info del modelo si existe
    try:
        tm = job.trained_model
        data['trained_model'] = {
            'id':       str(tm.pk),
            'module':   tm.module,
            'features': tm.features_json,
        }
    except TrainedModel.DoesNotExist:
        data['trained_model'] = None

    return JsonResponse(data)


# ──────────────────────────────────────────────────────────
# POST /api/training/evaluate/
# Body: multipart — model_id, file (.csv)
# ──────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(['POST'])
def evaluate_api(request):
    user = _require_auth(request)
    if not user:
        return _json_error('No autenticado.', 401)

    model_id    = request.POST.get('model_id')
    uploaded    = request.FILES.get('file')
    sample_size = request.POST.get('sample_size')

    if not model_id:
        return _json_error('Falta model_id.')
    if not uploaded:
        return _json_error('Falta el archivo CSV.')

    tm = get_object_or_404(TrainedModel, pk=model_id, job__user=user)

    sample_size = int(sample_size) if sample_size else None

    with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as tmp:
        for chunk in uploaded.chunks():
            tmp.write(chunk)
        tmp_path = tmp.name

    try:
        from training.evaluator import evaluate_with_csv, save_evaluation_to_job
        report = evaluate_with_csv(tmp_path, tm, sample_size=sample_size)

        # Persistir en el job
        save_evaluation_to_job(tm.job, report)

        return JsonResponse({
            'model_id':   str(tm.pk),
            'model_name': tm.name,
            'report':     report,
        })
    except Exception as e:
        logger.exception(e)
        return _json_error(str(e), 500)
    finally:
        os.unlink(tmp_path)
