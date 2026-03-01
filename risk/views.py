"""
Gestión de Riesgos TI — ISO 27005 / NIST RMF
Views: Dashboard, Registro de Riesgos, Activos TI, Vulnerabilidades, Auditoria
"""

from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from datetime import timedelta, date
import json, csv

from core.models import Organization, ITAsset, Risk, RiskReview, Vulnerability


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _get_org(request):
    try:
        return request.user.profile.organization
    except Exception:
        return None


def _require_org(request):
    """Return (org, None) on success, or (None, JsonResponse error) if no org."""
    org = _get_org(request)
    if org is None:
        return None, JsonResponse({'success': False, 'error': 'No organization associated with this account.'}, status=403)
    return org, None


def _risk_dict(r, include_description=True):
    return {
        'id': r.id,
        'title': r.title,
        'description': r.description if include_description else r.description[:150],
        'category': r.category,
        'category_label': r.get_category_display(),
        'likelihood': r.likelihood,
        'impact': r.impact,
        'risk_score': r.risk_score,
        'risk_level': r.risk_level,
        'status': r.status,
        'status_label': r.get_status_display(),
        'treatment_type': r.treatment_type,
        'treatment_type_label': r.get_treatment_type_display() if r.treatment_type else '',
        'treatment_plan': r.treatment_plan,
        'owner': r.owner,
        'due_date': r.due_date.isoformat() if r.due_date else None,
        'is_overdue': bool(r.due_date and r.due_date < date.today() and r.status not in ('mitigated', 'closed', 'accepted')),
        'residual_likelihood': r.residual_likelihood,
        'residual_impact': r.residual_impact,
        'residual_score': r.residual_score,
        'asset_id': r.affected_asset_id,
        'asset': r.affected_asset.name if r.affected_asset else None,
        'created_at': r.created_at.strftime('%d/%m/%Y'),
        'updated_at': r.updated_at.strftime('%d/%m/%Y'),
    }


# ─────────────────────────────────────────────────────────────────────────────
# TEMPLATE VIEW
# ─────────────────────────────────────────────────────────────────────────────

@login_required
def risk_dashboard_view(request):
    organization = _get_org(request)
    return render(request, 'risk/dashboard.html', {'organization': organization})


# ─────────────────────────────────────────────────────────────────────────────
# API — STATS GENERALES
# ─────────────────────────────────────────────────────────────────────────────

@login_required
def risk_stats(request):
    organization = _get_org(request)
    today = date.today()

    risks  = Risk.objects.filter(organization=organization)
    assets = ITAsset.objects.filter(organization=organization)
    vulns  = Vulnerability.objects.filter(organization=organization)

    active = risks.exclude(status__in=['mitigated', 'closed', 'accepted'])

    active_list = list(active.values_list('likelihood', 'impact', 'due_date', 'status'))
    critical_n = sum(1 for l, i, *_ in active_list if l * i >= 15)
    high_n     = sum(1 for l, i, *_ in active_list if 10 <= l * i < 15)
    medium_n   = sum(1 for l, i, *_ in active_list if 5  <= l * i < 10)
    low_n      = sum(1 for l, i, *_ in active_list if l * i < 5)

    overdue = sum(
        1 for l, i, due, st in active_list
        if due and due < today and st not in ('mitigated', 'closed', 'accepted')
    )

    matrix = {}
    for r in risks.exclude(status='closed').values('likelihood', 'impact'):
        key = f"{r['likelihood']},{r['impact']}"
        matrix[key] = matrix.get(key, 0) + 1

    by_cat = {}
    for cat, label in Risk.CATEGORY_CHOICES:
        c = risks.filter(category=cat).count()
        if c:
            by_cat[label] = c

    by_status = {}
    for st, label in Risk.STATUS_CHOICES:
        c = risks.filter(status=st).count()
        if c:
            by_status[st] = {'label': label, 'count': c}

    treatment = {}
    for tt, label in Risk.TREATMENT_CHOICES:
        c = active.filter(treatment_type=tt).count()
        if c:
            treatment[label] = c
    no_treatment = active.filter(treatment_type='').count()
    if no_treatment:
        treatment['Sin definir'] = no_treatment

    top_assets = []
    for a in assets.order_by('name')[:30]:
        rc = a.risks.exclude(status='closed').count()
        vc = a.vulnerabilities.filter(status__in=['open', 'in_progress']).count()
        if rc or vc:
            top_assets.append({'name': a.name, 'risks': rc, 'vulns': vc, 'criticality': a.criticality})
    top_assets = sorted(top_assets, key=lambda x: x['risks'] + x['vulns'], reverse=True)[:5]

    trend = []
    for i in range(11, -1, -1):
        d_start = (today.replace(day=1) - timedelta(days=i * 28)).replace(day=1)
        if i == 0:
            d_end = today
        else:
            d_end = (d_start + timedelta(days=31)).replace(day=1)
        cnt = risks.filter(created_at__date__gte=d_start, created_at__date__lt=d_end).count()
        trend.append({'month': d_start.strftime('%b %Y'), 'count': cnt})

    vuln_open     = vulns.filter(status__in=['open', 'in_progress']).count()
    vuln_critical = vulns.filter(severity='critical', status='open').count()
    vuln_by_sev = {}
    for sev, label in Vulnerability.SEVERITY_CHOICES:
        c = vulns.filter(severity=sev).exclude(status__in=['resolved', 'false_positive']).count()
        if c:
            vuln_by_sev[label] = c

    stats = {
        'total_risks': risks.count(),
        'active_risks': active.count(),
        'critical_risks': critical_n,
        'high_risks': high_n,
        'medium_risks': medium_n,
        'low_risks': low_n,
        'overdue_risks': overdue,
        'mitigated_risks': risks.filter(status='mitigated').count(),
        'accepted_risks': risks.filter(status='accepted').count(),
        'total_assets': assets.count(),
        'critical_assets': assets.filter(criticality='critical').count(),
        'open_vulns': vuln_open,
        'critical_vulns': vuln_critical,
        'vuln_by_severity': vuln_by_sev,
        'risk_matrix': matrix,
        'by_category': by_cat,
        'by_status': by_status,
        'treatment_breakdown': treatment,
        'top_assets_at_risk': top_assets,
        'trend': trend,
    }
    return JsonResponse({'success': True, 'stats': stats})


# ─────────────────────────────────────────────────────────────────────────────
# API — RIESGOS
# ─────────────────────────────────────────────────────────────────────────────

@login_required
def list_risks(request):
    organization = _get_org(request)
    qs = Risk.objects.filter(organization=organization).select_related('affected_asset')

    status_filter   = request.GET.get('status')
    category_filter = request.GET.get('category')
    level_filter    = request.GET.get('level')
    search          = request.GET.get('q', '').strip()
    overdue_only    = request.GET.get('overdue') == '1'

    if status_filter:
        qs = qs.filter(status=status_filter)
    if category_filter:
        qs = qs.filter(category=category_filter)
    if search:
        from django.db.models import Q
        qs = qs.filter(Q(title__icontains=search) | Q(description__icontains=search) | Q(owner__icontains=search))
    if overdue_only:
        qs = qs.filter(due_date__lt=date.today()).exclude(status__in=['mitigated', 'closed', 'accepted'])

    risks_data = []
    for r in qs.order_by('-likelihood', '-impact')[:200]:
        level = r.risk_level
        if level_filter and level != level_filter:
            continue
        risks_data.append(_risk_dict(r, include_description=False))

    return JsonResponse({'success': True, 'risks': risks_data})


@login_required
def risk_detail(request, risk_id):
    organization = _get_org(request)
    try:
        risk = Risk.objects.select_related('affected_asset', 'created_by').get(
            id=risk_id, organization=organization
        )
    except Risk.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Not found'}, status=404)

    reviews = list(RiskReview.objects.filter(risk=risk).select_related('reviewer').order_by('-reviewed_at')[:20])
    vulns = list(Vulnerability.objects.filter(linked_risk=risk).order_by('-discovery_date')[:10])

    data = _risk_dict(risk)
    data['reviews'] = [
        {
            'id': rv.id,
            'reviewer': rv.reviewer.get_full_name() or rv.reviewer.username if rv.reviewer else 'Sistema',
            'notes': rv.notes,
            'status_before': rv.status_before,
            'status_after': rv.status_after,
            'score_before': rv.likelihood_before * rv.impact_before,
            'score_after': rv.likelihood_after * rv.impact_after,
            'date': rv.reviewed_at.strftime('%d/%m/%Y %H:%M'),
        }
        for rv in reviews
    ]
    data['linked_vulns'] = [
        {'id': v.id, 'title': v.title, 'severity': v.severity, 'status': v.status, 'cvss_score': v.cvss_score}
        for v in vulns
    ]
    return JsonResponse({'success': True, 'risk': data})


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
            residual_likelihood=int(data['residual_likelihood']) if data.get('residual_likelihood') else None,
            residual_impact=int(data['residual_impact']) if data.get('residual_impact') else None,
            created_by=request.user,
        )
        return JsonResponse({'success': True, 'risk': _risk_dict(risk)})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@login_required
@require_http_methods(["POST"])
def update_risk(request, risk_id):
    try:
        organization = _get_org(request)
        risk = Risk.objects.get(id=risk_id, organization=organization)
        data = json.loads(request.body)

        changed = any(k in data for k in ('status', 'likelihood', 'impact'))
        if changed:
            RiskReview.objects.create(
                risk=risk,
                reviewer=request.user,
                notes=data.get('review_notes', 'Actualizacion manual'),
                status_before=risk.status,
                status_after=data.get('status', risk.status),
                likelihood_before=risk.likelihood,
                impact_before=risk.impact,
                likelihood_after=int(data.get('likelihood', risk.likelihood)),
                impact_after=int(data.get('impact', risk.impact)),
            )

        for field in ['title', 'description', 'category', 'status', 'treatment_type', 'treatment_plan', 'owner']:
            if field in data:
                setattr(risk, field, data[field])
        if 'likelihood'          in data: risk.likelihood          = int(data['likelihood'])
        if 'impact'              in data: risk.impact              = int(data['impact'])
        if 'due_date'            in data: risk.due_date            = data['due_date'] or None
        if 'residual_likelihood' in data: risk.residual_likelihood = int(data['residual_likelihood']) if data['residual_likelihood'] else None
        if 'residual_impact'     in data: risk.residual_impact     = int(data['residual_impact']) if data['residual_impact'] else None
        if 'asset_id'            in data: risk.affected_asset_id   = data['asset_id'] or None
        risk.save()
        return JsonResponse({'success': True, 'risk': _risk_dict(risk)})
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


@login_required
def export_risks_csv(request):
    organization = _get_org(request)
    risks = Risk.objects.filter(organization=organization).select_related('affected_asset').order_by('-likelihood', '-impact')

    response = HttpResponse(content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = 'attachment; filename="registro_riesgos.csv"'
    response.write('\ufeff')

    writer = csv.writer(response)
    writer.writerow(['ID', 'Titulo', 'Categoria', 'Probabilidad', 'Impacto', 'Puntuacion', 'Nivel',
                     'Estado', 'Tratamiento', 'Responsable', 'Activo', 'Vencimiento',
                     'P.Residual', 'I.Residual', 'Score Residual', 'Plan de tratamiento', 'Fecha creacion'])
    for r in risks:
        writer.writerow([
            r.id, r.title, r.get_category_display(), r.likelihood, r.impact, r.risk_score, r.risk_level.upper(),
            r.get_status_display(), r.get_treatment_type_display() if r.treatment_type else '',
            r.owner, r.affected_asset.name if r.affected_asset else '',
            r.due_date or '', r.residual_likelihood or '', r.residual_impact or '', r.residual_score or '',
            r.treatment_plan, r.created_at.strftime('%d/%m/%Y'),
        ])
    return response


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
            'description': a.description,
            'risk_count': a.risks.exclude(status='closed').count(),
            'critical_risk_count': sum(1 for r in a.risks.exclude(status='closed').values_list('likelihood', 'impact') if r[0]*r[1] >= 15),
            'vuln_count': a.vulnerabilities.filter(status__in=['open', 'in_progress']).count(),
            'critical_vuln_count': a.vulnerabilities.filter(severity='critical', status='open').count(),
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
    sev_filter    = request.GET.get('severity')
    search        = request.GET.get('q', '').strip()

    if status_filter:
        qs = qs.filter(status=status_filter)
    if sev_filter:
        qs = qs.filter(severity=sev_filter)
    if search:
        from django.db.models import Q
        qs = qs.filter(Q(title__icontains=search) | Q(cve_id__icontains=search))

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
            'asset_id': v.asset_id,
            'linked_risk': v.linked_risk.title[:60] if v.linked_risk else None,
            'linked_risk_id': v.linked_risk_id,
            'discovery_date': v.discovery_date.isoformat() if v.discovery_date else None,
            'due_date': v.due_date.isoformat() if v.due_date else None,
            'is_overdue': bool(v.due_date and v.due_date < date.today() and v.status not in ('resolved', 'false_positive')),
            'remediation_notes': v.remediation_notes,
        }
        for v in qs[:200]
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
            cvss_score=float(data['cvss_score']) if data.get('cvss_score') else None,
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
            vuln.cvss_score = float(data['cvss_score']) if data['cvss_score'] else None
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


# ─────────────────────────────────────────────────────────────────────────────
# SEED DEMO DATA
# ─────────────────────────────────────────────────────────────────────────────

@login_required
@require_http_methods(["POST"])
def seed_demo(request):
    try:
        organization = _get_org(request)

        if Risk.objects.filter(organization=organization).count() > 0:
            return JsonResponse({'success': False, 'error': 'Ya existen datos en el registro'})

        assets_data = [
            ('Servidor de Produccion Web', 'server',   'critical', 'ops@empresa.com',   '10.0.0.10', 'CPD Principal'),
            ('Base de Datos ERP',          'database', 'critical', 'dba@empresa.com',    '10.0.0.20', 'CPD Principal'),
            ('Portal de Clientes',         'app',      'high',     'dev@empresa.com',    '',          'AWS eu-west-1'),
            ('Firewall Perimetral',        'network',  'critical', 'netsec@empresa.com', '10.0.0.1',  'CPD Principal'),
            ('Office 365 / Exchange',      'cloud',    'high',     'it@empresa.com',     '',          'Microsoft Cloud'),
            ('VPN Corporativa',            'network',  'high',     'netsec@empresa.com', '10.0.0.5',  'CPD Principal'),
            ('Estaciones Desarrollo',      'workstation','medium', 'it@empresa.com',     '',          'Oficina Madrid'),
            ('Repositorio de Codigo',      'app',      'high',     'dev@empresa.com',    '',          'GitHub Enterprise'),
        ]
        asset_objs = {}
        for name, atype, crit, owner, ip, loc in assets_data:
            a = ITAsset.objects.create(organization=organization, name=name, asset_type=atype,
                                       criticality=crit, owner=owner, ip_address=ip, location=loc)
            asset_objs[name] = a

        today = date.today()

        risks_data = [
            ('Acceso no autorizado a base de datos de clientes',
             'Explotacion de credenciales debiles o SQL injection puede exponer datos personales de clientes.',
             'data', 5, 5, 'open', 'mitigate',
             'Implementar autenticacion multifactor, revisar permisos y auditar accesos diariamente.',
             'CISO', today + timedelta(days=30), 'Base de Datos ERP', 3, 4),

            ('Ransomware en infraestructura critica',
             'Campana de phishing dirigido puede infectar sistemas y cifrar activos criticos.',
             'cybersecurity', 4, 5, 'in_treatment', 'mitigate',
             'Segmentacion de red, backups offsite, EDR avanzado, simulacros de phishing mensuales.',
             'CISO', today + timedelta(days=15), 'Servidor de Produccion Web', 2, 5),

            ('Fuga de codigo fuente propietario',
             'Desarrolladores con acceso excesivo pueden filtrar codigo fuente a competidores.',
             'data', 3, 4, 'in_treatment', 'mitigate',
             'Implementar DLP, revisar permisos de repositorios, activar alertas de exfiltracion.',
             'CTO', today + timedelta(days=45), 'Repositorio de Codigo', 2, 3),

            ('Interrupcion del portal de clientes',
             'Ataque DDoS o fallo de infraestructura cloud puede dejar el servicio inaccesible.',
             'operational', 3, 4, 'open', 'mitigate',
             'Contratar servicio anti-DDoS, implementar CDN, disenio arquitectura multi-AZ.',
             'CTO', today + timedelta(days=60), 'Portal de Clientes', None, None),

            ('Incumplimiento GDPR por fuga de datos',
             'Brecha de seguridad en sistemas de datos personales puede acarrear sanciones regulatorias.',
             'compliance', 3, 5, 'open', 'mitigate',
             'Auditoria de flujos de datos, DPO designado, politica de retencion y cifrado.',
             'Legal', today + timedelta(days=20), 'Base de Datos ERP', None, None),

            ('Compromiso de credenciales de O365',
             'Ataque de fuerza bruta o phishing puede comprometer cuentas corporativas de email.',
             'cybersecurity', 4, 3, 'in_treatment', 'mitigate',
             'MFA obligatorio, Conditional Access Policies, formacion a usuarios.',
             'IT Security', today + timedelta(days=10), 'Office 365 / Exchange', 2, 2),

            ('Proveedor tercero con acceso a sistemas internos',
             'Proveedor de mantenimiento tiene acceso VPN sin monitoreo adecuado.',
             'third_party', 3, 3, 'open', 'mitigate',
             'PAM (Privileged Access Management), grabacion de sesiones, revision trimestral.',
             'Auditoria', today - timedelta(days=5), 'VPN Corporativa', None, None),

            ('Fallo de backup en produccion',
             'Los backups del servidor de produccion no se verifican, riesgo de perdida de datos.',
             'operational', 2, 5, 'in_treatment', 'mitigate',
             'Automatizar verificacion de backups, almacenamiento en al menos 3 ubicaciones.',
             'Ops', today + timedelta(days=90), 'Servidor de Produccion Web', 1, 4),

            ('Shadow IT: herramientas cloud no autorizadas',
             'Empleados usan Dropbox y otras apps personales para compartir informacion corporativa.',
             'compliance', 4, 3, 'accepted', 'accept',
             'Riesgo aceptado tras analisis coste-beneficio. Monitoreo ligero implementado.',
             'CISO', None, None, None, None),

            ('Vulnerabilidades en dependencias de software',
             'Librerias de terceros desactualizadas en la aplicacion web presentan CVEs conocidas.',
             'cybersecurity', 4, 4, 'open', 'mitigate',
             'Implementar SCA (Software Composition Analysis) en CI/CD pipeline.',
             'Dev Lead', today + timedelta(days=14), 'Portal de Clientes', 2, 3),

            ('Perdida de laptop con datos sensibles',
             'Dispositivos de empleados sin cifrado de disco completo pueden exponer datos en caso de robo.',
             'data', 3, 3, 'mitigated', 'mitigate',
             'BitLocker activado en todos los dispositivos, politica de bloqueo automatico.',
             'IT', None, 'Estaciones Desarrollo', 1, 1),

            ('Acceso fisico no autorizado al CPD',
             'Control de acceso fisico al centro de datos sin doble factor biometrico.',
             'infrastructure', 2, 4, 'in_treatment', 'mitigate',
             'Instalar torniquetes biometricos, registros de acceso, CCTV 24/7.',
             'Facilities', today + timedelta(days=120), 'Servidor de Produccion Web', 1, 3),
        ]

        for (title, desc, cat, lik, imp, status, treat_type, plan, owner, due, asset_name, res_l, res_i) in risks_data:
            asset = asset_objs.get(asset_name) if asset_name else None
            Risk.objects.create(
                organization=organization, title=title, description=desc,
                category=cat, likelihood=lik, impact=imp, status=status,
                treatment_type=treat_type, treatment_plan=plan, owner=owner,
                due_date=due, affected_asset=asset,
                residual_likelihood=res_l, residual_impact=res_i,
                created_by=request.user,
            )

        server = asset_objs.get('Servidor de Produccion Web')
        portal = asset_objs.get('Portal de Clientes')
        db     = asset_objs.get('Base de Datos ERP')

        vulns_data = [
            ('Log4Shell RCE en servidor de aplicaciones', 'CVE-2021-44228', 'critical', 10.0, 'open', server,
             'Actualizar a Log4j 2.17.0+, aplicar workaround de JNDI lookup.'),
            ('SQL Injection en formulario de busqueda', '', 'high', 8.8, 'in_progress', portal,
             'Parametrizar todas las consultas, implementar WAF rules.'),
            ('OpenSSL Heartbleed', 'CVE-2014-0160', 'high', 7.5, 'resolved', server,
             'Actualizado a OpenSSL 1.0.1g. Certificados renovados.'),
            ('Cross-Site Scripting persistente en comentarios', '', 'medium', 6.1, 'open', portal,
             'Sanitizar input, implementar CSP header.'),
            ('MySQL sin autenticacion remota deshabilitada', '', 'critical', 9.8, 'open', db,
             'Deshabilitar acceso remoto root, revisar grants.'),
            ('Certificado SSL expirado en ambiente staging', '', 'low', 3.1, 'resolved', portal,
             'Automatizar renovacion con Lets Encrypt.'),
            ('Spring4Shell RCE', 'CVE-2022-22965', 'critical', 9.8, 'in_progress', portal,
             'Actualizar Spring Framework a 5.3.18+.'),
            ('Struts2 Remote Code Execution', 'CVE-2017-5638', 'critical', 10.0, 'open', server,
             'Actualizar Apache Struts a version parcheada, aplicar WAF virtual patch.'),
        ]

        risk_objs = list(Risk.objects.filter(organization=organization))
        for i, (title, cve, sev, cvss, status, asset, remedy) in enumerate(vulns_data):
            Vulnerability.objects.create(
                organization=organization, title=title, cve_id=cve, severity=sev,
                cvss_score=cvss, status=status, asset=asset,
                remediation_notes=remedy,
                discovery_date=today - timedelta(days=i * 12 + 3),
                due_date=today + timedelta(days=30 - i * 5) if status not in ('resolved',) else None,
                linked_risk=risk_objs[i % len(risk_objs)] if risk_objs else None,
            )

        return JsonResponse({'success': True, 'message': f'Datos demo cargados: {len(risks_data)} riesgos, {len(assets_data)} activos, {len(vulns_data)} vulnerabilidades'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
