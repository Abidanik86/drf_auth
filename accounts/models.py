from random import randint

from django.contrib.auth.models import AbstractUser , BaseUserManager
from django.db import models
from django.utils import timezone



class CustomUserManager(BaseUserManager):

    def create_user(self,email,username,password=None):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email,username=username)
        user.set_password(password)
        user.save(using=self._db)
        
        return user
    
    def create_superuser(self,email,username,password=None):
        user = self.create_user(email=email,username=username,password=password)
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        
        return user
    

class CustomUserProfile(AbstractUser):
    email = models.EmailField(unique=True)
    
    first_name =models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    
    date_joined = models.DateTimeField(auto_now_add=True)
    
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    
    email_confirmed = models.BooleanField(default=False , verbose_name='Email Confirmed')
    email_verification_code = models.CharField(max_length=100, blank=True, null=True , verbose_name='Verification Code')
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    def __str__(self):
        return self.email    
    
    
class AccountActivation(models.Model):
    user = models.OneToOneField(CustomUserProfile, on_delete=models.CASCADE , related_name='email_confirmation')
    activation_code = models.CharField(max_length=100 , blank=True, null=True , verbose_name= ('Activation Code'))
    created_at = models.DateTimeField(default=timezone.now , verbose_name= ('Creation Time'))
    
    def __str__(self):
        return f"Email Confirmation for {self.user.email}"
    
    def create_confirmation(self):
        code = str(randint(100000, 999999))
        self.activation_code = code
        self.save()
        return code
    
    def verify_confirmation(self, code):
        if code == self.activation_code:
            self.user.email_confirmed = True
            self.user.save()
            return True
        
        return False