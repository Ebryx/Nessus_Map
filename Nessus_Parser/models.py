# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models

# Create your models here.
class Vulnerability(models.Model):
    pluginId = models.IntegerField()
    title = models.CharField(max_length=500)
    count = models.IntegerField()
    risk = models.CharField(max_length=100)
    files = models.SlugField()
    description = models.SlugField()

    # @classmethod
    # def create(pluginId, title, count, risk, files, description):
    #     vulnerability = self(pluginId=pluginId, title=title, count=count, risk=risk, files=files, description=description)
    #     return vulnerability


class Hosts(models.Model):
    pluginId = models.IntegerField()
    host_ip = models.CharField(max_length=50)
    detail = models.SlugField()



