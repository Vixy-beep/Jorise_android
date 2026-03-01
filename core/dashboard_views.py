from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from datetime import timedelta
from core.models import SecurityEvent, SIEMLog, EDRAgent, WAFLog, SandboxAnalysis
from django.db.models import Count, Q
from django.http import JsonResponse
from django.core.cache import cache
import json
import requests as http_requests

@login_required
def dashboard_view(request):
    """Main dashboard view showing SOC overview"""
    try:
        organization = request.user.profile.organization
    except Exception:
        organization = None

    # Superusers without an org go to admin
    if organization is None:
        if request.user.is_superuser:
            return redirect('/admin/')
        return redirect('/login/')

    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    
    # Get all events from last 24h
    events = SecurityEvent.objects.filter(
        organization=organization,
        timestamp__gte=last_24h
    )
    
    subscription = getattr(organization, 'subscription', None)

    # Calculate stats
    stats = {
        'total_events': events.count(),
        'critical_alerts': events.filter(severity='critical').count(),
        'blocked_attacks': events.filter(action_taken__isnull=False).count(),
        'threat_level': calculate_threat_level(organization),
        'siem': {},
        'edr': {},
        'waf': {}
    }
    
    # SIEM stats if enabled
    if subscription and subscription.siem_enabled:
        siem_logs = SIEMLog.objects.filter(
            organization=organization,
            timestamp__gte=last_24h
        )
        stats['siem'] = {
            'logs_analyzed': siem_logs.count(),
            'anomalies': siem_logs.filter(threat_detected=True).count()
        }
    
    # EDR stats if enabled
    if subscription and subscription.edr_enabled:
        edr_agents = EDRAgent.objects.filter(organization=organization)
        stats['edr'] = {
            'active_endpoints': edr_agents.filter(
                status='online',
                last_seen__gte=now - timedelta(minutes=15)
            ).count(),
            'threats': events.filter(
                event_type='edr',
                severity__in=['critical', 'high']
            ).count()
        }
    
    # WAF stats if enabled
    if subscription and subscription.waf_enabled:
        waf_logs = WAFLog.objects.filter(
            organization=organization,
            timestamp__gte=last_24h
        )
        stats['waf'] = {
            'requests_analyzed': waf_logs.count(),
            'blocked': waf_logs.filter(blocked=True).count()
        }
    
    # Recent incidents (last 10)
    recent_incidents = []
    for event in events.order_by('-timestamp')[:10]:
        incident = {
            'title': event.event_type.upper() + ' - ' + (event.source_ip or 'Unknown'),
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


def _geolocate_ips(ip_list):
    """
    Geolocate a list of IPs using ip-api.com batch endpoint.
    Results are cached per IP for 24h to avoid rate limits.
    Returns dict: {ip: {lat, lon, country, city}}
    """
    result = {}
    to_query = []

    for ip in ip_list:
        if not ip or ip.startswith(('10.', '192.168.', '172.', '127.')):
            continue  # skip private IPs
        cached = cache.get(f'geo_{ip}')
        if cached:
            result[ip] = cached
        else:
            to_query.append(ip)

    # Batch geolocate in chunks of 100 (ip-api limit)
    for i in range(0, len(to_query), 100):
        chunk = to_query[i:i+100]
        try:
            resp = http_requests.post(
                'http://ip-api.com/batch',
                json=[{'query': ip, 'fields': 'query,lat,lon,country,city,status'} for ip in chunk],
                timeout=5
            )
            if resp.status_code == 200:
                for item in resp.json():
                    if item.get('status') == 'success':
                        geo = {
                            'lat': item['lat'],
                            'lon': item['lon'],
                            'country': item.get('country', ''),
                            'city': item.get('city', ''),
                        }
                        result[item['query']] = geo
                        cache.set(f'geo_{item["query"]}', geo, 86400)  # 24h
        except Exception:
            pass  # no romper el dashboard si ip-api falla

    return result


@login_required
def threat_map_data(request):
    """
    API endpoint: devuelve los últimos eventos con geo para el mapa de amenazas.
    GET /api/threat-map/
    """
    organization = request.user.profile.organization
    last_24h = timezone.now() - timedelta(hours=24)

    events = SecurityEvent.objects.filter(
        organization=organization,
        timestamp__gte=last_24h,
        source_ip__isnull=False,
    ).values('source_ip', 'severity', 'source_lat', 'source_lon',
             'source_country', 'source_city').order_by('-timestamp')[:500]

    # Collect IPs that still need geolocation
    needs_geo = [e['source_ip'] for e in events if not e['source_lat']]
    geo_map = _geolocate_ips(list(set(needs_geo)))

    # Build response and update DB for cached results
    points = {}
    for ev in events:
        ip = ev['source_ip']
        lat = ev['source_lat']
        lon = ev['source_lon']
        country = ev['source_country'] or ''
        city = ev['source_city'] or ''

        if not lat and ip in geo_map:
            lat = geo_map[ip]['lat']
            lon = geo_map[ip]['lon']
            country = geo_map[ip]['country']
            city = geo_map[ip]['city']
            # Persist geo to avoid future API calls
            SecurityEvent.objects.filter(
                source_ip=ip, source_lat__isnull=True, organization=organization
            ).update(source_lat=lat, source_lon=lon,
                     source_country=country, source_city=city)

        if lat and lon:
            key = f'{lat:.2f},{lon:.2f}'
            if key not in points:
                points[key] = {
                    'lat': lat, 'lon': lon,
                    'country': country, 'city': city,
                    'count': 0, 'severity': ev['severity']
                }
            points[key]['count'] += 1
            # escalate severity
            sev_order = ['info', 'low', 'medium', 'high', 'critical']
            if sev_order.index(ev['severity']) > sev_order.index(points[key]['severity']):
                points[key]['severity'] = ev['severity']

    return JsonResponse({'points': list(points.values())})
