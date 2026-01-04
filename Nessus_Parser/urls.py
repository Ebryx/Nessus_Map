from django.urls import include
from django.urls import re_path as url
from . import views

app_name = 'nessus'

urlpatterns = [
    url(r'^vulnerabilities/$', views.parse_XML, name='nessusparse'),
    url(r'^toggle-finding/$', views.toggle_finding, name='toggle-finding'),
    url(r'upload/$', views.upload_file, name='upload'),
    url(r'services/$', views.do_port_filter, name='services'),
    url(r'parseOS/$', views.do_parse_os, name='parseos'),
    url(r'executive-report/$', views.generate_executive_report, name='executive-report'),
    url(r'gen-html', views.generate_html_report, name="gen-html-report"),
    url(r'gen-json', views.generate_json_file, name="gen-json"),
    url(r'load-json', views.load_json_file, name="load-json")
]

