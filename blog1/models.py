from __future__ import unicode_literals

from django.db import models

# Create your models here.


class InsDatabase(models.Model):
    code = models.CharField(max_length=64)
    arch = models.CharField(max_length=64)
    data = models.TextField()