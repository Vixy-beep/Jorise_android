"""
Authentication views - Login, Register, Logout
"""
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse
from core.models import Organization, Subscription
import uuid


def login_view(request):
    """Login page"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            next_url = request.GET.get('next', 'dashboard')
            return redirect(next_url)
        else:
            messages.error(request, 'Usuario o contraseña incorrectos')
    
    return render(request, 'auth/login.html')


def register_view(request):
    """Register new user and organization"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        org_name = request.POST.get('organization_name')
        plan = request.POST.get('plan', 'free')
        
        # Validations
        if password != password2:
            messages.error(request, 'Las contraseñas no coinciden')
            return render(request, 'auth/register.html')
        
        if User.objects.filter(username=username).exists():
            messages.error(request, 'El usuario ya existe')
            return render(request, 'auth/register.html')
        
        if User.objects.filter(email=email).exists():
            messages.error(request, 'El email ya está registrado')
            return render(request, 'auth/register.html')
        
        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=request.POST.get('first_name', ''),
            last_name=request.POST.get('last_name', ''),
        )
        
        # Create organization
        org = Organization.objects.create(
            name=org_name,
            domain=f"{username}.jorise.app",
            is_active=True
        )
        
        # Create subscription based on plan
        plan_configs = {
            'free': {
                'max_events_per_month': 1000,
                'max_endpoints': 5,
                'max_api_calls_per_day': 100,
                'siem_enabled': False,
                'edr_enabled': False,
                'waf_enabled': False,
                'antivirus_enabled': True,
                'sandbox_enabled': True,
                'ai_analysis_enabled': False,
            },
            'pro': {
                'max_events_per_month': 50000,
                'max_endpoints': 50,
                'max_api_calls_per_day': 5000,
                'siem_enabled': True,
                'edr_enabled': True,
                'waf_enabled': True,
                'antivirus_enabled': True,
                'sandbox_enabled': True,
                'ai_analysis_enabled': True,
            },
            'enterprise': {
                'max_events_per_month': 1000000,
                'max_endpoints': 1000,
                'max_api_calls_per_day': 100000,
                'siem_enabled': True,
                'edr_enabled': True,
                'waf_enabled': True,
                'antivirus_enabled': True,
                'sandbox_enabled': True,
                'ai_analysis_enabled': True,
            }
        }
        
        config = plan_configs.get(plan, plan_configs['free'])
        
        Subscription.objects.create(
            organization=org,
            plan=plan,
            status='trialing' if plan != 'free' else 'active',
            **config
        )
        
        # Associate user with organization (through profile - create if needed)
        user.profile.organization = org
        user.profile.save()
        
        # Login user
        login(request, user)
        messages.success(request, '¡Cuenta creada exitosamente!')
        
        return redirect('dashboard')
    
    return render(request, 'auth/register.html')


def logout_view(request):
    """Logout user"""
    logout(request)
    messages.success(request, 'Sesión cerrada exitosamente')
    return redirect('login')
