"""
Gestión de Riesgos TI — ISO 27005 / NIST RMF
Views: Dashboard, Registro de Riesgos, Activos TI, Vulnerabilidades
"""

from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from datetime import timedelta, date
import json

from core.models import (
    Organization, ITAsset, Risk, RiskReview, Vulnerability
)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _get_org(request):
    return request.user.profile.organization


RISK_LEVEL_COLOR = {
    'critical': '#ef4444',
    'high':     '#f97316',
    'medium':   '#eab308',
    'low':      '#22c55e',
}


def _risk_level(score):
    if score >= 15:
        return 'critical'
    elif score >= 10:
        return 'high'
    elif score >= 5:
        return 'medium'
    return 'low'


# ─────────────────────────────────────────────────────────────────────────────
# TEMPLATE VIEW
# ─────────────────────────────────────────────────────────────────────────────

@login_required
def risk_dashboard_view(request):
    """Renderiza el dashboard de gestión de riesgos."""
    organization = _get_org(request)
    return render(request, 'risk/dashboard.html', {'organization': organization})


# ─────────────────────────────────────────────────────────────────────────────
# API — STATS GENERALES
# ─────────────────────────────────────────────────────────────────────────────

@login_required
def risk_stats(request):
    """Devuelve estadísticas resumidas para el dashboard."""
    organization = _get_org(request)

    risks = Risk.objects.filter(organization=organization)
    assets = ITAsset.objects.filter(organization=organization)
    vulns = Vulnerability.objects.filter(organization=organization)

    open_risks = risks.exclude(status__in=['mitigated', 'closed', 'accepted'])

    # Matriz de riesgo 5×5 (cuenta por celda likelihood×impact)
    matrix = {}
    for r in risks.exclude(status='closed'):
        key = f"{r.likelihood},{r.impact}"
        matrix[key] = matrix.get(key, 0) + 1

    stats = {
        'total_risks': risks.count(),
        'open_risks': open_risks.count(),
        'critical_risks': sum(1 for r in open_risks if r.risk_level == 'critical'),
        'high_risks': sum(1 for r in open_risks if r.risk_level == 'high'),
        'mitigated_risks': risks.filter(status='mitigated').count(),
        'accepted_risks': risks.filter(status='accepted').count(),
        'total_assets': assets.count(),
        'critical_assets': assets.filter(criticality='critical').count(),
        'open_vulns': vulns.filter(status__in=['open', 'in_progress']).count(),
        'critical_vulns': vulns.filter(severity='critical', status='open').count(),
        'risk_matrix': matrix,
        'by_category': {},
        'by_status': {},
    }

    for cat, label in Risk.CATEGORY_CHOICES:
        cnt = risks.filter(category=cat).count()
        if cnt:
            stats['by_category'][label] = cnt

    for st, label in Risk.STATUS_CHOICES:
        cnt = risks.filter(status=st).count()
        if cnt:
            stats['by_status'][label] = cnt

    return JsonResponse({'success': True, 'stats': stats})


# ─────────────────────────────────────────────────────────────────────────────
# API — RIESGOS
# ─────────────────────────────────────────────────────────────────────────────

@login_required
def list_risks(request):
    """Lista de riesgos con filtros opcionales."""
    organization = _get_org(request)

    qs = Risk.objects.filter(organization=organization).select_related('affected_asset')

    status_filter = request.GET.get('status')
    category_filter = request.GET.get('category')
    level_filter = request.GET.get('level')

    if status_filter:
        qs = qs.filter(status=status_filter)
    if category_filter:
        qs = qs.filter(category=category_filter)

    risks = []
    for r in qs[:100]:
        level = r.risk_level
        if level_filter and level != level_filter:
            continue
        risks.append({
            'id': r.id,
            'title': r.title,
            'description': r.description[:200],
            'category': r.category,
            'category_label': r.get_category_display(),
            'likelihood': r.likelihood,
            'impact': r.impact,
            'risk_score': r.risk_score,
            'risk_level': level,
            'status': r.status,
            'status_label': r.get_status_display(),
            'treatment_type': r.treatment_type,
            'treatment_plan': r.treatment_plan,
            'owner': r.owner,
            'due_date': r.due_date.isoformat() if r.due_date else None,
            'residual_score': r.residual_score,
            'asset': r.affected_asset.name if r.affected_asset else None,
            'created_at': r.created_at.strftime('%d/%m/%Y'),
        })

    return JsonResponse({'success': True, 'risks': risks})


@login_required
@require_http_methods(["POST"])
def create_risk(request):
    try:
        organization = _get_org(request)
        data = json.loads(request.body)

        risk = Risk.objects.create(
            organization=organization,
            title=data['title'],
            description=data.get('description', ''),
            category=data['category'],
            likelihood=int(data['likelihood']),
            impact=int(data['impact']),
            status=data.get('status', 'open'),
            treatment_type=data.get('treatment_type', ''),
            treatment_plan=data.get('treatment_plan', ''),
            owner=data.get('owner', ''),
            due_date=data.get('due_date') or None,
            affected_asset_id=data.get('asset_id') or None,
            residual_likelihood=data.get('residual_likelihood') or None,
            residual_impact=data.get('residual_impact') or None,
            created_by=request.user,
        )
        return JsonResponse({'success': True, 'id': risk.id, 'risk_score': risk.risk_score, 'risk_level': risk.risk_level})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@login_required
@require_http_methods(["POST"])
def update_risk(request, risk_id):
    try:
        organization = _get_org(request)
        risk = Risk.objects.get(id=risk_id, organization=organization)
        data = json.loads(request.body)

        # Save review snapshot before update
        if 'status' in data or 'likelihood' in data or 'impact' in data:
            RiskReview.objects.create(
                risk=risk,
                reviewer=request.user,
                notes=data.get('review_notes', 'Actualización'),
                status_before=risk.status,
                status_after=data.get('status', risk.status),
                likelihood_before=risk.likelihood,
                impact_before=risk.impact,
                likelihood_after=int(data.get('likelihood', risk.likelihood)),
                impact_after=int(data.get('impact', risk.impact)),
            )

        for field in ['title', 'description', 'category', 'status', 'treatment_type',
                      'treatment_plan', 'owner']:
            if field in data:
                setattr(risk, field, data[field])
        if 'likelihood' in data:
            risk.likelihood = int(data['likelihood'])
        if 'impact' in data:
            risk.impact = int(data['impact'])
        if 'due_date' in data:
            risk.due_date = data['due_date'] or None
        if 'residual_likelihood' in data:
            risk.residual_likelihood = data['residual_likelihood'] or None
        if 'residual_impact' in data:
            risk.residual_impact = data['residual_impact'] or None
        if 'asset_id' in data:
            risk.affected_asset_id = data['asset_id'] or None
        risk.save()
        return JsonResponse({'success': True, 'risk_score': risk.risk_score, 'risk_level': risk.risk_level})
    except Risk.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Risk not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@login_required
@require_http_methods(["POST"])
def delete_risk(request, risk_id):
    try:
        organization = _get_org(request)
        Risk.objects.filter(id=risk_id, organization=organization).delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


# ─────────────────────────────────────────────────────────────────────────────
# API — ACTIVOS TI
# ─────────────────────────────────────────────────────────────────────────────

@login_required
def list_assets(request):
    organization = _get_org(request)
    assets = ITAsset.objects.filter(organization=organization, is_active=True)
    return JsonResponse({'success': True, 'assets': [
        {
            'id': a.id,
            'name': a.name,
            'asset_type': a.asset_type,
            'asset_type_label': a.get_asset_type_display(),
            'criticality': a.criticality,
            'criticality_label': a.get_criticality_display(),
            'owner': a.owner,
            'ip_address': a.ip_address,
            'location': a.location,
            'risk_count': a.risks.exclude(status='closed').count(),
            'vuln_count': a.vulnerabilities.filter(status__in=['open', 'in_progress']).count(),
        }
        for a in assets
    ]})


@login_required
@require_http_methods(["POST"])
def create_asset(request):
    try:
        organization = _get_org(request)
        data = json.loads(request.body)
        asset = ITAsset.objects.create(
            organization=organization,
            name=data['name'],
            asset_type=data['asset_type'],
            description=data.get('description', ''),
            owner=data.get('owner', ''),
            ip_address=data.get('ip_address', ''),
            location=data.get('location', ''),
            criticality=data.get('criticality', 'medium'),
        )
        return JsonResponse({'success': True, 'id': asset.id, 'name': asset.name})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@login_required
@require_http_methods(["POST"])
def delete_asset(request, asset_id):
    try:
        organization = _get_org(request)
        ITAsset.objects.filter(id=asset_id, organization=organization).delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


# ─────────────────────────────────────────────────────────────────────────────
# API — VULNERABILIDADES
# ─────────────────────────────────────────────────────────────────────────────

@login_required
def list_vulnerabilities(request):
    organization = _get_org(request)
    qs = Vulnerability.objects.filter(organization=organization).select_related('asset', 'linked_risk')

    status_filter = request.GET.get('status')
    if status_filter:
        qs = qs.filter(status=status_filter)

    return JsonResponse({'success': True, 'vulnerabilities': [
        {
            'id': v.id,
            'title': v.title,
            'description': v.description[:200],
            'cve_id': v.cve_id,
            'severity': v.severity,
            'severity_label': v.get_severity_display(),
            'status': v.status,
            'status_label': v.get_status_display(),
            'cvss_score': v.cvss_score,
            'asset': v.asset.name if v.asset else None,
            'linked_risk': v.linked_risk.title if v.linked_risk else None,
            'discovery_date': v.discovery_date.isoformat() if v.discovery_date else None,
            'due_date': v.due_date.isoformat() if v.due_date else None,
            'remediation_notes': v.remediation_notes,
        }
        for v in qs[:100]
    ]})


@login_required
@require_http_methods(["POST"])
def create_vulnerability(request):
    try:
        organization = _get_org(request)
        data = json.loads(request.body)
        vuln = Vulnerability.objects.create(
            organization=organization,
            title=data['title'],
            description=data.get('description', ''),
            cve_id=data.get('cve_id', ''),
            severity=data['severity'],
            status=data.get('status', 'open'),
            cvss_score=data.get('cvss_score') or None,
            remediation_notes=data.get('remediation_notes', ''),
            discovery_date=data.get('discovery_date') or date.today(),
            due_date=data.get('due_date') or None,
            asset_id=data.get('asset_id') or None,
            linked_risk_id=data.get('risk_id') or None,
        )
        return JsonResponse({'success': True, 'id': vuln.id})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@login_required
@require_http_methods(["POST"])
def update_vulnerability(request, vuln_id):
    try:
        organization = _get_org(request)
        vuln = Vulnerability.objects.get(id=vuln_id, organization=organization)
        data = json.loads(request.body)
        for field in ['title', 'description', 'cve_id', 'severity', 'status', 'remediation_notes']:
            if field in data:
                setattr(vuln, field, data[field])
        if 'status' in data and data['status'] == 'resolved' and not vuln.resolved_date:
            vuln.resolved_date = date.today()
        if 'cvss_score' in data:
            vuln.cvss_score = data['cvss_score'] or None
        if 'due_date' in data:
            vuln.due_date = data['due_date'] or None
        if 'asset_id' in data:
            vuln.asset_id = data['asset_id'] or None
        if 'risk_id' in data:
            vuln.linked_risk_id = data['risk_id'] or None
        vuln.save()
        return JsonResponse({'success': True})
    except Vulnerability.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@login_required
@require_http_methods(["POST"])
def delete_vulnerability(request, vuln_id):
    try:
        organization = _get_org(request)
        Vulnerability.objects.filter(id=vuln_id, organization=organization).delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)
