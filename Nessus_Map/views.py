from django.shortcuts import render, redirect
from django.conf import settings
from filebrowser.base import FileListing

def home_view(request):
    filelisting = FileListing(settings.MEDIA_ROOT, sorting_by='date', sorting_order='desc')
    files = filelisting.listing()
    return render(request, 'index.html', {'files' : files})

