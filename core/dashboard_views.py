from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from datetime import timedelta
from core.models import SecurityEvent, SIEMLog, EDRAgent, WAFLog, SandboxAnalysis
from django.db.models import Count, Q
import json

@login_required
def dashboard_view(request):
    """Main dashboard view showing SOC overview"""
    organization = request.user.profile.organization
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    
    # Get all events from last 24h
    events = SecurityEvent.objects.filter(
        organization=organization,
        timestamp__gte=last_24h
    )
    
    # Calculate stats
    stats = {
        'total_events': events.count(),
        'critical_alerts': events.filter(severity='critical').count(),
        'blocked_attacks': events.filter(status='blocked').count(),
        'threat_level': calculate_threat_level(organization),
        'siem': {},
        'edr': {},
        'waf': {}
    }
    
    # SIEM stats if enabled
    if organization.subscription.siem_enabled:
        siem_logs = SIEMLog.objects.filter(
            organization=organization,
            timestamp__gte=last_24h
        )
        stats['siem'] = {
            'logs_analyzed': siem_logs.count(),
            'anomalies': siem_logs.filter(anomaly_detected=True).count()
        }
    
    # EDR stats if enabled
    if organization.subscription.edr_enabled:
        edr_agents = EDRAgent.objects.filter(organization=organization)
        stats['edr'] = {
            'active_endpoints': edr_agents.filter(
                status='active',
                last_seen__gte=now - timedelta(minutes=15)
            ).count(),
            'threats': events.filter(
                event_type='edr',
                severity__in=['critical', 'high']
            ).count()
        }
    
    # WAF stats if enabled
    if organization.subscription.waf_enabled:
        waf_logs = WAFLog.objects.filter(
            organization=organization,
            timestamp__gte=last_24h
        )
        stats['waf'] = {
            'requests_analyzed': waf_logs.count(),
            'blocked': waf_logs.filter(action='blocked').count()
        }
    
    # Recent incidents (last 10)
    recent_incidents = []
    for event in events.order_by('-timestamp')[:10]:
        incident = {
            'title': event.event_type.upper() + ' - ' + event.source,
            'description': event.description[:100],
            'severity': event.severity,
            'timestamp': event.timestamp,
            'icon': get_event_icon(event.event_type)
        }
        recent_incidents.append(incident)
    
    # Chart data for events timeline (last 24 hours by hour)
    chart_labels = []
    chart_data = []
    for i in range(24):
        hour_start = now - timedelta(hours=23-i)
        hour_end = hour_start + timedelta(hours=1)
        count = events.filter(
            timestamp__gte=hour_start,
            timestamp__lt=hour_end
        ).count()
        chart_labels.append(hour_start.strftime('%H:00'))
        chart_data.append(count)
    
    # Attack types distribution
    attack_types = events.values('event_type').annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    
    attack_types_labels = [item['event_type'].upper() for item in attack_types]
    attack_types_data = [item['count'] for item in attack_types]
    
    context = {
        'stats': stats,
        'recent_incidents': recent_incidents,
        'chart_labels': json.dumps(chart_labels),
        'chart_data': json.dumps(chart_data),
        'attack_types_labels': json.dumps(attack_types_labels),
        'attack_types_data': json.dumps(attack_types_data)
    }
    
    return render(request, 'dashboard/index.html', context)


@login_required
def subscription_management(request):
    """Subscription management page"""
    organization = request.user.profile.organization
    subscription = organization.subscription
    
    # Calculate usage stats
    now = timezone.now()
    current_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    usage = {
        'events_this_month': SecurityEvent.objects.filter(
            organization=organization,
            timestamp__gte=current_month_start
        ).count(),
        'siem_logs_this_month': SIEMLog.objects.filter(
            organization=organization,
            timestamp__gte=current_month_start
        ).count() if subscription.siem_enabled else 0,
        'waf_requests_this_month': WAFLog.objects.filter(
            organization=organization,
            timestamp__gte=current_month_start
        ).count() if subscription.waf_enabled else 0,
        'sandbox_analyses_this_month': SandboxAnalysis.objects.filter(
            organization=organization,
            created_at__gte=current_month_start
        ).count(),
    }
    
    # Plan limits
    limits = get_plan_limits(subscription.plan)
    
    context = {
        'subscription': subscription,
        'usage': usage,
        'limits': limits,
        'days_until_renewal': (subscription.end_date - now.date()).days if subscription.end_date else None
    }
    
    return render(request, 'dashboard/subscription.html', context)


@login_required
def settings_view(request):
    """Settings page"""
    return render(request, 'dashboard/settings.html')


def calculate_threat_level(organization):
    """Calculate overall threat level based on recent events"""
    now = timezone.now()
    last_hour = now - timedelta(hours=1)
    
    events = SecurityEvent.objects.filter(
        organization=organization,
        timestamp__gte=last_hour
    )
    
    critical_count = events.filter(severity='critical').count()
    high_count = events.filter(severity='high').count()
    
    if critical_count >= 5:
        return 'critical'
    elif critical_count >= 1 or high_count >= 10:
        return 'high'
    elif high_count >= 3:
        return 'medium'
    else:
        return 'low'


def get_event_icon(event_type):
    """Get emoji icon for event type"""
    icons = {
        'siem': '📈',
        'edr': '💻',
        'waf': '🛡️',
        'sandbox': '🔬',
        'firewall': '🔥',
        'antivirus': '🦠'
    }
    return icons.get(event_type, '⚠️')


def get_plan_limits(plan):
    """Get limits for subscription plan"""
    limits = {
        'free': {
            'events_per_month': 10000,
            'siem_logs_per_month': 5000,
            'waf_requests_per_month': 50000,
            'sandbox_analyses_per_month': 10,
            'retention_days': 7,
            'ai_reports': False
        },
        'pro': {
            'events_per_month': 100000,
            'siem_logs_per_month': 50000,
            'waf_requests_per_month': 500000,
            'sandbox_analyses_per_month': 100,
            'retention_days': 30,
            'ai_reports': True
        },
        'enterprise': {
            'events_per_month': -1,  # Unlimited
            'siem_logs_per_month': -1,
            'waf_requests_per_month': -1,
            'sandbox_analyses_per_month': -1,
            'retention_days': 365,
            'ai_reports': True
        }
    }
    return limits.get(plan, limits['free'])
