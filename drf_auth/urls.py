"""
URL configuration for drf_auth project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from accounts import  views
urlpatterns = [
    
    path("admin/", admin.site.urls),
    
    path('profile/', views.Account.as_view(), name = 'profile'),
    path('edit-profile-details/', views.AccountChange.as_view(), name='edit-profile-details'),
    
    path('signup/', views.SignUpView.as_view(), name='signup'),

    path('activate-account/', views.AccountActivationView.as_view(), name='account-activation'),
    
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='login'),
    
    path('password-change/', views.PasswordChangeView.as_view(), name='password-change'),
    path('password-reset/', views.PasswordResetView.as_view(), name='password-reset'),
    path('password-reset/verify/', views.PasswordResetVerifyView.as_view(), name='password-reset-verify'),
    
    path('email-change/', views.EmailChangeView.as_view(), name='email-change'),
    path('email-change/verify/', views.EmailChangeVerifyView.as_view(), name='email-change-verify'),
]
