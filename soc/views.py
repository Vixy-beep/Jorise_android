"""
SOC (Security Operations Center) Dashboard
Main dashboard aggregating all security modules
"""

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.db.models import Count, Q, Avg
from datetime import timedelta
import json
from core.models import (
    SecurityEvent, Organization, Subscription,
    EDRAgent, WAFLog, SandboxAnalysis, SIEMLog,
    ThreatIntelligence
)


@require_http_methods(["GET"])
def soc_dashboard(request, org_id):
    """Dashboard principal del SOC"""
    try:
        organization = Organization.objects.get(id=org_id)
        subscription = organization.subscription
        
        # Verificar acceso
        if subscription.plan == 'free':
            return JsonResponse({
                'error': 'SOC Dashboard requires Pro or Enterprise plan'
            }, status=403)
        
        cutoff_24h = timezone.now() - timedelta(hours=24)
        cutoff_7d = timezone.now() - timedelta(days=7)
        
        # === MÉTRICAS GLOBALES ===
        events_24h = SecurityEvent.objects.filter(
            organization=organization,
            timestamp__gte=cutoff_24h
        )
        
        # Threat Level global
        critical_events = events_24h.filter(severity='critical').count()
        high_events = events_24h.filter(severity='high').count()
        
        if critical_events > 5:
            global_threat_level = 'CRITICAL'
            threat_color = 'red'
        elif critical_events > 0 or high_events > 10:
            global_threat_level = 'HIGH'
            threat_color = 'orange'
        elif high_events > 0:
            global_threat_level = 'ELEVATED'
            threat_color = 'yellow'
        else:
            global_threat_level = 'LOW'
            threat_color = 'green'
        
        # === EVENTOS POR MÓDULO ===
        events_by_module = dict(
            events_24h.values('module')
            .annotate(count=Count('id'))
            .values_list('module', 'count')
        )
        
        # === MÓDULOS ESTADÍSTICAS ===
        modules_stats = []
        
        # 1. SIEM
        if subscription.siem_enabled:
            siem_logs_24h = SIEMLog.objects.filter(
                organization=organization,
                timestamp__gte=cutoff_24h
            ).count()
            
            siem_threats = SIEMLog.objects.filter(
                organization=organization,
                timestamp__gte=cutoff_24h,
                threat_detected=True
            ).count()
            
            modules_stats.append({
                'name': 'SIEM',
                'status': 'active',
                'badge': 'Alerts' if siem_threats > 0 else 'Active',
                'badge_color': 'warning' if siem_threats > 0 else 'success',
                'metrics': {
                    'logs_ingested_24h': siem_logs_24h,
                    'threats_detected': siem_threats,
                    'anomalies': events_24h.filter(module='siem').count(),
                }
            })
        
        # 2. EDR
        if subscription.edr_enabled:
            total_agents = EDRAgent.objects.filter(organization=organization).count()
            online_agents = EDRAgent.objects.filter(
                organization=organization,
                status='online'
            ).count()
            
            suspicious_processes = events_24h.filter(module='edr').count()
            
            modules_stats.append({
                'name': 'EDR',
                'status': 'monitoring' if online_agents > 0 else 'ready',
                'badge': 'Monitoring' if online_agents > 0 else 'Ready',
                'badge_color': 'info',
                'metrics': {
                    'total_endpoints': total_agents,
                    'online_endpoints': online_agents,
                    'suspicious_processes': suspicious_processes,
                }
            })
        
        # 3. WAF
        if subscription.waf_enabled:
            waf_requests_24h = WAFLog.objects.filter(
                organization=organization,
                timestamp__gte=cutoff_24h
            ).count()
            
            waf_blocked = WAFLog.objects.filter(
                organization=organization,
                timestamp__gte=cutoff_24h,
                blocked=True
            ).count()
            
            protection_rate = (waf_blocked / waf_requests_24h * 100) if waf_requests_24h > 0 else 0
            
            modules_stats.append({
                'name': 'WAF',
                'status': 'protecting',
                'badge': 'Protecting',
                'badge_color': 'success',
                'metrics': {
                    'requests_analyzed': waf_requests_24h,
                    'attacks_blocked': waf_blocked,
                    'protection_rate': f'{protection_rate:.1f}%',
                }
            })
        
        # 4. ANTIVIRUS
        if subscription.antivirus_enabled:
            av_scans_7d = SandboxAnalysis.objects.filter(
                organization=organization,
                created_at__gte=cutoff_7d,
                status='completed'
            ).count()
            
            av_threats = SandboxAnalysis.objects.filter(
                organization=organization,
                created_at__gte=cutoff_7d,
                verdict='malicious'
            ).count()
            
            modules_stats.append({
                'name': 'ANTIVIRUS',
                'status': 'scanning' if av_threats > 0 else 'no_alerts',
                'badge': 'Scanning' if av_scans_7d > 0 else 'No alerts',
                'badge_color': 'danger' if av_threats > 0 else 'success',
                'metrics': {
                    'scans_last_7d': av_scans_7d,
                    'threats_found': av_threats,
                }
            })
        
        # 5. SANDBOX
        if subscription.sandbox_enabled:
            sandbox_analyses_7d = SandboxAnalysis.objects.filter(
                organization=organization,
                created_at__gte=cutoff_7d
            ).count()
            
            sandbox_pending = SandboxAnalysis.objects.filter(
                organization=organization,
                status__in=['queued', 'running']
            ).count()
            
            modules_stats.append({
                'name': 'SANDBOX',
                'status': 'ready' if sandbox_pending == 0 else 'running',
                'badge': f'{sandbox_pending} Alerts' if sandbox_pending > 0 else 'Ready',
                'badge_color': 'info' if sandbox_pending > 0 else 'success',
                'metrics': {
                    'analyses_last_7d': sandbox_analyses_7d,
                    'pending_analyses': sandbox_pending,
                }
            })
        
        # === INCIDENTES RECIENTES ===
        recent_incidents = events_24h.filter(
            severity__in=['high', 'critical']
        ).order_by('-timestamp')[:10]
        
        incidents_data = [{
            'id': str(incident.id),
            'timestamp': incident.timestamp.strftime('%H:%M'),
            'type': incident.event_type.replace('_', ' ').title(),
            'module': incident.module.upper(),
            'severity': incident.severity.upper(),
            'is_resolved': incident.is_resolved,
        } for incident in recent_incidents]
        
        # === THREAT INTELLIGENCE ===
        recent_threats = ThreatIntelligence.objects.filter(
            last_seen__gte=cutoff_7d
        ).order_by('-last_seen')[:5]
        
        threats_data = [{
            'ioc_type': threat.get_ioc_type_display(),
            'ioc_value': threat.ioc_value[:50],
            'threat_level': threat.threat_level.upper(),
            'description': threat.description[:100],
        } for threat in recent_threats]
        
        # === SYSTEM STATUS ===
        system_status = {
            'all_systems_operational': all([
                stat['status'] in ['active', 'monitoring', 'protecting', 'no_alerts', 'ready']
                for stat in modules_stats
            ]),
            'modules_enabled': len(modules_stats),
        }
        
        # === RESPONSE ===
        dashboard_data = {
            'success': True,
            'organization': {
                'id': str(organization.id),
                'name': organization.name,
                'plan': subscription.get_plan_display(),
            },
            'global_threat_level': {
                'level': global_threat_level,
                'color': threat_color,
                'description': f'Elevated due to recent APT campaigns' if global_threat_level in ['HIGH', 'CRITICAL'] else 'No major threats detected',
            },
            'overview_stats': {
                'total_events_24h': events_24h.count(),
                'critical_events': critical_events,
                'active_incidents': events_24h.filter(is_resolved=False).count(),
                'system_health': '99.97%',
            },
            'modules': modules_stats,
            'recent_incidents': incidents_data,
            'threat_intelligence': {
                'global_threat_level': global_threat_level,
                'top_threats': threats_data,
            },
            'system_status': system_status,
        }
        
        return JsonResponse(dashboard_data)
        
    except Organization.DoesNotExist:
        return JsonResponse({'error': 'Organization not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["GET"])
def soc_dashboard_html(request, org_id):
    """Vista HTML del dashboard SOC"""
    try:
        organization = Organization.objects.get(id=org_id)
        
        context = {
            'organization': organization,
            'subscription': organization.subscription,
        }
        
        return render(request, 'soc/dashboard.html', context)
        
    except Organization.DoesNotExist:
        return JsonResponse({'error': 'Organization not found'}, status=404)


@require_http_methods(["GET"])
def get_events_timeline(request, org_id):
    """Obtiene timeline de eventos para gráficos"""
    try:
        organization = Organization.objects.get(id=org_id)
        
        hours = int(request.GET.get('hours', 24))
        cutoff = timezone.now() - timedelta(hours=hours)
        
        events = SecurityEvent.objects.filter(
            organization=organization,
            timestamp__gte=cutoff
        )
        
        # Agrupar por hora
        from django.db.models.functions import TruncHour
        
        timeline = events.annotate(
            hour=TruncHour('timestamp')
        ).values('hour', 'severity').annotate(
            count=Count('id')
        ).order_by('hour')
        
        # Formatear para chart.js
        data_by_severity = {}
        for entry in timeline:
            severity = entry['severity']
            if severity not in data_by_severity:
                data_by_severity[severity] = []
            
            data_by_severity[severity].append({
                'x': entry['hour'].isoformat(),
                'y': entry['count']
            })
        
        return JsonResponse({
            'success': True,
            'timeline': data_by_severity
        })
        
    except Organization.DoesNotExist:
        return JsonResponse({'error': 'Organization not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
