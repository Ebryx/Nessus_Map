from django.conf.urls import url, include
from . import views

app_name = 'nessus'

urlpatterns = [
    url(r'^vulnerabilities/$', views.parse_XML, name='nessusparse'),
    url(r'upload/$', views.upload_file, name='upload'),
    url(r'services/$', views.do_port_filter, name='services'),
    url(r'parseOS/$', views.do_parse_os, name='parseos'),
    url(r'executive-report/$', views.generate_executive_report, name='executive-report'),
]

