from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from django.utils.translation import gettext as _
from django.contrib.auth.password_validation import validate_password

from rest_framework import serializers

from rest_framework.exceptions import ValidationError

User = get_user_model()

class SignupSerializer(serializers.ModelSerializer):
    
    password = serializers.CharField(write_only=True, required=True , style={'input_type':'password'})
    
    class Meta:
        model = get_user_model()
        fields = ['email','username','password']
        
    def create(self, validated_data):
        user = get_user_model().objects.create_user(**validated_data)
        
        return user
    
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'})

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'), email=email, password=password)

            if user:
                if not user.email_confirmed:
                    raise serializers.ValidationError(_('Email not confirmed. Please activate your account.'))

                data['user'] = user
                return data
            else:
                raise serializers.ValidationError(_('Invalid email or password.'))
        else:
            raise serializers.ValidationError(_('Must include "email" and "password".'))
        

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('id', 'email', 'first_name', 'last_name')
        
    def validate_email(self, value):
        """
        Check that the email provided is in the database.
        """
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email does not exist.")
        return value

    def validate(self, data):
        """
        Perform custom validation across multiple fields or raise
        generic errors like data not found.
        """
        if 'email' in data and not User.objects.filter(email=data['email']).exists():
            raise ValidationError({'email': 'No user found with this email.'})
        return data

    def to_representation(self, instance):
        """
        Override to_representation to handle cases where the instance is None.
        """
        if instance is None:
            raise ValidationError('User not available or does not exist.')
        return super().to_representation(instance)

class AccountActivationSerializer(serializers.Serializer):
    code = serializers.CharField()


class ProfileChangeSerializer(serializers.Serializer):
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)
    
class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    

class PasswordResetVerifySerializer(serializers.Serializer):
    code = serializers.CharField()
    new_password = serializers.CharField(write_only=True, style={'input_type': 'password'}, validators=[validate_password])


class EmailChangeSerializer(serializers.Serializer):
    email = serializers.EmailField()


class EmailChangeVerifySerializer(serializers.Serializer):
    code = serializers.CharField()
    new_email = serializers.EmailField()


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    new_password = serializers.CharField(write_only=True, validators=[validate_password], style={'input_type': 'password'})