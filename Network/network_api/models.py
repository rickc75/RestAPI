from django.db import models
from django.contrib.auth.models import AbstractUser,BaseUserManager
from django.utils.translation import gettext as _
from django.utils import timezone
from random import randint

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)
    
class CustomUser(AbstractUser):
    name = models.CharField(max_length=100)
    contact = models.PositiveBigIntegerField(null=True)
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    email_confirmed = models.BooleanField(default=False, verbose_name=_('Email Confirmed'))
    email_verification_code = models.CharField(max_length=6, null=True, blank=True, verbose_name=_('Verification code'))
    objects = CustomUserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']
    def __str__(self):
        return self.email
    
class AccountActivation(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='email_confirmation')
    activation_code = models.CharField(max_length=6, null=True, blank=True, verbose_name=_('Activation Code'))
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_('Creation Time'))

    def __str__(self):
        return f"Email Confirmation for {self.user.email}"

    def create_confirmation(self):
        code = str(randint(100000, 999999))  # Generate a random 6-digit code
        self.activation_code = code
        self.save()
        return code

    def verify_confirmation(self, code):
        if self.activation_code == code:
            self.user.email_confirmed = True
            self.user.save()
            self.delete()  # Remove the confirmation record
            return True

        # Invalid confirmation code
        return False


class KnowledgeBase(models.Model):
    knowledgeBase_ID = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    short_description = models.CharField(max_length=100)
    domain_group = models.CharField(max_length=100)
    type = models.CharField(max_length=100)

class KnowledgeBaseFile(models.Model):
     knowledgebase = models.ForeignKey(KnowledgeBase, on_delete=models.CASCADE, related_name='paths')
     name = models.CharField(max_length=100)
     type = models.CharField(max_length=100)
     path = models.FileField(upload_to="knowledgebases")
     def save(self, *args, **kwargs):
        if self.path: 
            self.name = self.path.name
            self.type = self.path.name.split('.')[-1]
        super().save(*args, **kwargs)

class PromptMgmt(models.Model):
    knowledgebase = models.ForeignKey(KnowledgeBase, on_delete=models.CASCADE,related_name='messages')
    name = models.CharField(max_length=100)
    message = models.CharField(max_length=100)
    provider = models.CharField(max_length=100)
    model = models.CharField(max_length=100)
    tag_ID = models.IntegerField(unique=True)
    audit_fields = models.CharField(max_length=100)


