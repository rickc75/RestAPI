from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from rest_framework.validators import UniqueValidator
from .models import KnowledgeBase,KnowledgeBaseFile,PromptMgmt
User = get_user_model()

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('id', 'email', 'first_name', 'last_name')

class ProfileChangeSerializer(serializers.Serializer):
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)

class SignUpSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    class Meta:
        model = User
        fields = ['first_name','last_name','email', 'password', 'contact']
        extra_kwargs = {"password": {"write_only": True}}
    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user       
    
class AccountActivationSerializer(serializers.Serializer):
    code = serializers.CharField()

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetVerifySerializer(serializers.Serializer):
    code = serializers.CharField()
    new_password = serializers.CharField(write_only=True, style={'input_type': 'password'}, validators=[validate_password])


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    new_password = serializers.CharField(write_only=True, validators=[validate_password], style={'input_type': 'password'})

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        # Authenticate user using the custom backend
        if email and password:
            user = authenticate(email=email, password=password)
            if user is None:
                if not User.objects.filter(email=email).exists():
                    raise serializers.ValidationError("User does not exist")
                else:
                    raise serializers.ValidationError("User exists and password is incorrect")
            if user:
                if not user.email_confirmed:
                    raise serializers.ValidationError('Email not confirmed. Please activate your account.')

            # If authentication is successful, return the user
            data['user'] = user
            return data
        else:
            raise serializers.ValidationError('Must include "email" and "password".')
    
class KnowledgeBaseFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = KnowledgeBaseFile
        fields = "__all__"

    
class PromptMgmtSerializer(serializers.ModelSerializer):
    class Meta:
        model = PromptMgmt
        fields = "__all__"
        def create(self, validated_data):
            prompt = PromptMgmt.objects.create_user(**validated_data)
            return prompt    

class KnowledgeBaseSerializer(serializers.ModelSerializer):
    paths = KnowledgeBaseFileSerializer(many=True, read_only=True)
    uploaded_paths = serializers.ListField(child=serializers.FileField(allow_empty_file=False, use_url=False),write_only=True)
    class Meta:
        model = KnowledgeBase
        fields = ["name", "short_description", "domain_group", "type","paths","uploaded_paths"]
    def create(self, validated_data):
        uploaded_paths = validated_data.pop("uploaded_paths")
        knowledgebase = KnowledgeBase.objects.create(**validated_data)
        for path in uploaded_paths:
            KnowledgeBaseFile.objects.create(knowledgebase=knowledgebase, path=path)
        return knowledgebase
        



    
