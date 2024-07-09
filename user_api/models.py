from django.db import models
from django.contrib.auth.models import AbstractUser
import uuid
import random
import string

class UUIDMixin(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)

    class Meta:
        abstract = True

class User(AbstractUser, UUIDMixin):
    pass
    
class Permissions(models.Model):
    name = models.CharField(max_length=255, unique=True)
    code = models.CharField(max_length=100, unique=True)

    def save(self, *args, **kwargs):
        if not self.code:
            self.code = self.name.upper()+''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

class Role(UUIDMixin, models.Model):
    name = models.CharField(max_length=255, unique=True)
    permissions = models.ManyToManyField(Permissions, related_name='roles')
    users = models.ManyToManyField(User, related_name='roles')

    def __str__(self):
        return self.name
