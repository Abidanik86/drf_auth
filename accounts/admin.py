from django.contrib import admin

# Register your models here.
from .models import CustomUserProfile

admin.site.register(CustomUserProfile)