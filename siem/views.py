"""
SIEM (Security Information and Event Management) Module
IA-powered log analysis, correlation, and threat detection
"""

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from datetime import timedelta
try:
    import google.generativeai as genai
except ImportError:
    genai = None
from django.conf import settings
import json
import re
from core.models import (
    SecurityEvent, SIEMLog, ThreatIntelligence, 
    Organization, UsageMetrics
)
from django.db.models import Count, Q
from collections import defaultdict

# Motor ML de Jorise (integración modelos entrenados)
try:
    from training.jorise_engine import JoriseEngine as _JoriseEngine
    JORISE_ML_AVAILABLE = True
except Exception:
    _JoriseEngine = None
    JORISE_ML_AVAILABLE = False

# Configurar Gemini AI (opcional)
try:
    import google.generativeai as genai
    if settings.GEMINI_API_KEY:
        genai.configure(api_key=settings.GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-pro')
        GEMINI_AVAILABLE = True
    else:
        GEMINI_AVAILABLE = False
        model = None
except (ImportError, Exception):
    GEMINI_AVAILABLE = False
    model = None


class SIEMAnalyzer:
    """Motor de análisis SIEM con IA"""
    
    @staticmethod
    def parse_log(raw_log, source):
        """Parsea un log usando IA para extraer información"""
        if not GEMINI_AVAILABLE or not model:
            # Fallback: parsing básico sin IA
            return {
                'message': raw_log[:200],
                'log_level': 'INFO',
                'source': source,
                'raw': raw_log
            }
        
        try:
            prompt = f"""
            Analiza este log de seguridad y extrae la información relevante en formato JSON:
            
            Fuente: {source}
            Log: {raw_log}
            
            Extrae:
            - timestamp
            - log_level (INFO, WARNING, ERROR, CRITICAL)
            - source_ip (si existe)
            - action (qué acción se realizó)
            - user (si existe)
            - message (resumen)
            - threat_indicators (lista de IOCs detectados)
            
            Responde SOLO con JSON válido, sin explicaciones.
            """
            
            response = model.generate_content(prompt)
            parsed = json.loads(response.text)
            return parsed
        except:
            # Fallback: parsing básico
            return {
                'message': raw_log[:200],
                'log_level': 'INFO',
                'raw': raw_log
            }
    
    @staticmethod
    def detect_anomalies(logs, organization):
        """Detecta anomalías en logs usando ML"""
        anomaly_score = 0.0
        reasons = []
        
        # 1. Tasa inusual de eventos
        recent_count = logs.filter(
            timestamp__gte=timezone.now() - timedelta(minutes=5)
        ).count()
        
        avg_count = logs.filter(
            timestamp__gte=timezone.now() - timedelta(hours=1)
        ).count() / 12  # Promedio por 5 minutos
        
        if recent_count > avg_count * 3:
            anomaly_score += 0.3
            reasons.append(f"Tasa de eventos elevada: {recent_count} vs promedio {avg_count:.1f}")
        
        # 2. IPs sospechosas
        recent_ips = logs.filter(
            timestamp__gte=timezone.now() - timedelta(minutes=5),
            source_ip__isnull=False
        ).values_list('source_ip', flat=True)
        
        for ip in recent_ips:
            threat = ThreatIntelligence.objects.filter(
                ioc_type='ip',
                ioc_value=ip
            ).first()
            
            if threat:
                anomaly_score += 0.5
                reasons.append(f"IP maliciosa detectada: {ip} ({threat.description})")
        
        # 3. Patrones sospechosos con IA
        if recent_count > 10 and GEMINI_AVAILABLE and model:
            log_messages = list(logs.filter(
                timestamp__gte=timezone.now() - timedelta(minutes=5)
            ).values_list('message', flat=True)[:20])
            
            try:
                prompt = f"""
                Analiza estos logs de seguridad y detecta patrones sospechosos:
                
                {chr(10).join(log_messages)}
                
                ¿Hay indicios de:
                - Escaneo de puertos
                - Fuerza bruta
                - Inyección SQL
                - Exfiltración de datos
                - Movimiento lateral
                
                Responde con JSON: {{"suspicious": true/false, "threat_type": "...", "confidence": 0-1}}
                """
                
                response = model.generate_content(prompt)
                result = json.loads(response.text)
                
                if result.get('suspicious'):
                    anomaly_score += result.get('confidence', 0.5)
                    reasons.append(f"Patrón sospechoso: {result.get('threat_type')}")
            except:
                pass
        
        # 4. Jorise ML — enriquece el score con los modelos entrenados
        if JORISE_ML_AVAILABLE and _JoriseEngine is not None:
            try:
                # Construir resumen del tráfico reciente para el motor ML
                log_data = {
                    'fwd_packets':     recent_count,
                    'packets_per_sec': recent_count / 300.0,   # ventana 5 min
                    'bytes_per_sec':   recent_count * 150.0,   # estimado ~ 150 B/evento
                    'avg_pkt_size':    150.0,
                }
                anomaly_score, reasons = _JoriseEngine.enrich_anomaly_score(
                    anomaly_score, reasons, log_data
                )
            except Exception as _ml_err:
                reasons.append(f"[Jorise ML] Error: {_ml_err}")
        
        return min(anomaly_score, 1.0), reasons
    
    @staticmethod
    def correlate_events(organization, time_window_minutes=10):
        """Correlaciona eventos para detectar ataques complejos"""
        cutoff = timezone.now() - timedelta(minutes=time_window_minutes)
        
        events = SecurityEvent.objects.filter(
            organization=organization,
            timestamp__gte=cutoff,
            is_resolved=False
        ).order_by('-timestamp')
        
        correlations = []
        
        # Agrupar por IP de origen
        ip_groups = defaultdict(list)
        for event in events:
            if event.source_ip:
                ip_groups[event.source_ip].append(event)
        
        # Detectar múltiples eventos de la misma IP
        for ip, ip_events in ip_groups.items():
            if len(ip_events) >= 3:
                modules = set(e.module for e in ip_events)
                
                # Si afecta múltiples módulos = ataque coordinado
                if len(modules) >= 2:
                    correlations.append({
                        'type': 'coordinated_attack',
                        'source_ip': ip,
                        'events': [str(e.id) for e in ip_events],
                        'modules_affected': list(modules),
                        'severity': 'critical',
                        'description': f'Ataque coordinado desde {ip} afectando {len(modules)} módulos'
                    })
        
        # Detectar escalada de privilegios
        for ip, ip_events in ip_groups.items():
            severities = [e.severity for e in sorted(ip_events, key=lambda x: x.timestamp)]
            
            if len(severities) >= 3:
                severity_order = ['info', 'low', 'medium', 'high', 'critical']
                indices = [severity_order.index(s) for s in severities]
                
                # Si la severidad va aumentando
                if all(indices[i] <= indices[i+1] for i in range(len(indices)-1)):
                    correlations.append({
                        'type': 'escalation_pattern',
                        'source_ip': ip,
                        'events': [str(e.id) for e in ip_events],
                        'severity': 'high',
                        'description': f'Patrón de escalada detectado desde {ip}'
                    })
        
        return correlations
    
    @staticmethod
    def generate_threat_report(organization, timeframe_hours=24):
        """Genera reporte de amenazas usando IA"""
        cutoff = timezone.now() - timedelta(hours=timeframe_hours)
        
        events = SecurityEvent.objects.filter(
            organization=organization,
            timestamp__gte=cutoff
        )
        
        stats = {
            'total_events': events.count(),
            'by_severity': dict(events.values('severity').annotate(count=Count('id')).values_list('severity', 'count')),
            'by_module': dict(events.values('module').annotate(count=Count('id')).values_list('module', 'count')),
            'critical_events': events.filter(severity='critical').count(),
            'unresolved': events.filter(is_resolved=False).count(),
        }
        
        # Top amenazas
        top_events = events.filter(
            severity__in=['high', 'critical']
        ).order_by('-timestamp')[:10]
        
        event_summaries = [
            f"- [{e.get_severity_display()}] {e.title} ({e.get_module_display()})"
            for e in top_events
        ]
        
        try:
            prompt = f"""
            Genera un reporte ejecutivo de seguridad para las últimas {timeframe_hours} horas.
            
            Estadísticas:
            - Total de eventos: {stats['total_events']}
            - Críticos: {stats['critical_events']}
            - Sin resolver: {stats['unresolved']}
            
            Eventos principales:
            {chr(10).join(event_summaries)}
            
            Genera un reporte profesional que incluya:
            1. Resumen ejecutivo
            2. Principales amenazas detectadas
            3. Recomendaciones de acción inmediata
            4. Tendencias observadas
            
            Formato: Markdown
            """
            
            response = model.generate_content(prompt)
            return response.text
        except:
            return "Error generando reporte con IA"


@require_http_methods(["GET"])
def siem_dashboard(request, org_id):
    """Dashboard principal SIEM"""
    try:
        organization = Organization.objects.get(id=org_id)
        
        # Verificar suscripción
        if not organization.subscription.siem_enabled:
            return JsonResponse({
                'error': 'SIEM module not enabled for this organization'
            }, status=403)
        
        # Métricas últimas 24h
        cutoff_24h = timezone.now() - timedelta(hours=24)
        
        events = SecurityEvent.objects.filter(
            organization=organization,
            timestamp__gte=cutoff_24h
        )
        
        logs = SIEMLog.objects.filter(
            organization=organization,
            timestamp__gte=cutoff_24h
        )
        
        stats = {
            'total_events': events.count(),
            'critical_events': events.filter(severity='critical').count(),
            'high_events': events.filter(severity='high').count(),
            'unresolved_events': events.filter(is_resolved=False).count(),
            'total_logs_ingested': logs.count(),
            'threats_detected': logs.filter(threat_detected=True).count(),
            
            'events_by_severity': dict(
                events.values('severity').annotate(count=Count('id')).values_list('severity', 'count')
            ),
            
            'events_by_module': dict(
                events.values('module').annotate(count=Count('id')).values_list('module', 'count')
            ),
            
            'top_source_ips': list(
                events.filter(source_ip__isnull=False)
                .values('source_ip')
                .annotate(count=Count('id'))
                .order_by('-count')[:10]
            ),
        }
        
        # Eventos recientes
        recent_events = events.order_by('-timestamp')[:20]
        
        events_data = [{
            'id': str(e.id),
            'timestamp': e.timestamp.isoformat(),
            'module': e.module,
            'severity': e.severity,
            'title': e.title,
            'source_ip': e.source_ip,
            'is_resolved': e.is_resolved,
        } for e in recent_events]
        
        # Detectar correlaciones
        correlations = SIEMAnalyzer.correlate_events(organization)
        
        return JsonResponse({
            'success': True,
            'stats': stats,
            'recent_events': events_data,
            'correlations': correlations,
        })
        
    except Organization.DoesNotExist:
        return JsonResponse({'error': 'Organization not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["POST"])
def ingest_log(request, org_id):
    """Ingesta de logs para análisis SIEM"""
    try:
        organization = Organization.objects.get(id=org_id)
        
        if not organization.subscription.siem_enabled:
            return JsonResponse({'error': 'SIEM not enabled'}, status=403)
        
        data = json.loads(request.body)
        
        raw_log = data.get('log')
        source = data.get('source', 'unknown')
        
        # Parsear log con IA
        parsed = SIEMAnalyzer.parse_log(raw_log, source)
        
        # Crear entrada de log
        log = SIEMLog.objects.create(
            organization=organization,
            source=source,
            log_level=parsed.get('log_level', 'INFO'),
            message=parsed.get('message', raw_log[:200]),
            raw_log=raw_log,
            parsed_data=parsed,
            source_ip=parsed.get('source_ip'),
        )
        
        # Detectar anomalías
        recent_logs = SIEMLog.objects.filter(organization=organization)
        anomaly_score, reasons = SIEMAnalyzer.detect_anomalies(recent_logs, organization)
        
        log.anomaly_score = anomaly_score
        log.ai_classified = True
        
        # Si es sospechoso, crear evento
        if anomaly_score > 0.6:
            log.threat_detected = True
            
            event = SecurityEvent.objects.create(
                organization=organization,
                module='siem',
                event_type='anomaly_detected',
                severity='high' if anomaly_score > 0.8 else 'medium',
                title=f"Anomalía detectada en logs de {source}",
                description=f"Score: {anomaly_score:.2f}\n\nRazones:\n" + "\n".join(reasons),
                source_ip=parsed.get('source_ip'),
                raw_data={'log_id': log.id, 'reasons': reasons},
                ai_confidence=anomaly_score,
            )
            
            log.related_event = event
        
        log.save()
        
        # Actualizar métricas
        today = timezone.now().date()
        metrics, _ = UsageMetrics.objects.get_or_create(
            organization=organization,
            date=today
        )
        metrics.logs_ingested += 1
        metrics.save()
        
        return JsonResponse({
            'success': True,
            'log_id': log.id,
            'anomaly_score': anomaly_score,
            'threat_detected': log.threat_detected,
        })
        
    except Organization.DoesNotExist:
        return JsonResponse({'error': 'Organization not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["GET"])
def generate_report(request, org_id):
    """Genera reporte de amenazas con IA"""
    try:
        organization = Organization.objects.get(id=org_id)
        
        timeframe = int(request.GET.get('hours', 24))
        
        report = SIEMAnalyzer.generate_threat_report(organization, timeframe)
        
        return JsonResponse({
            'success': True,
            'report': report,
            'generated_at': timezone.now().isoformat(),
        })
        
    except Organization.DoesNotExist:
        return JsonResponse({'error': 'Organization not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# Template views for web dashboard
from django.contrib.auth.decorators import login_required

@login_required
def siem_dashboard_view(request):
    """SIEM dashboard template view"""
    organization = request.user.profile.organization
    
    if not organization.subscription.siem_enabled:
        return render(request, 'dashboard/module_disabled.html', {
            'module_name': 'SIEM',
            'plan_required': 'Pro'
        })
    
    # Get recent logs
    recent_logs = SIEMLog.objects.filter(
        organization=organization
    ).order_by('-timestamp')[:50]
    
    # Get stats
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    
    stats = {
        'total_logs': SIEMLog.objects.filter(organization=organization).count(),
        'anomalies_24h': SIEMLog.objects.filter(
            organization=organization,
            timestamp__gte=last_24h,
            anomaly_detected=True
        ).count(),
        'critical_events': SIEMLog.objects.filter(
            organization=organization,
            log_level='CRITICAL'
        ).count(),
    }
    
    context = {
        'recent_logs': recent_logs,
        'stats': stats,
        'organization': organization,
    }
    
    return render(request, 'siem/dashboard.html', context)
