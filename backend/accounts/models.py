from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.utils import timezone
import uuid

class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('userPortfolio', 'UserPortfolio'),
        ('guest', 'Guest'),
    ]

    email = models.EmailField(unique=True)
    role = models.CharField(max_length=30, choices=ROLE_CHOICES, default='userPortfolio')
    is_email_verified = models.BooleanField(default=False)
    email_verification_token = models.UUIDField(default=uuid.uuid4)
    email_verification_token_created = models.DateTimeField(auto_now_add=True)
    verification_attempts = models.IntegerField(default=0)
    last_verification_attempt = models.DateTimeField(null=True, blank=True)
    
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    def __str__(self) -> str:
        return self.email
    
    def is_verification_token_valid(self):
        if not self.email_verification_token_created:
            return False
        expiry_time = self.email_verification_token_created + timezone.timedelta(hours=24)
        return timezone.now() <= expiry_time
    
    def can_attempt_verification(self):
        if not self.last_verification_attempt:
            return True
        cooldown_period = timezone.timedelta(minutes=15)
        return timezone.now() >= self.last_verification_attempt + cooldown_period

    def save(self, *args, **kwargs):
        if not self.email_verification_token:
            self.email_verification_token = uuid.uuid4()
        super().save(*args, **kwargs)

class PasswordResetToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_valid(self):
        return timezone.now() <= self.expires_at
