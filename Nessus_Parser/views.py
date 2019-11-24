from __future__ import unicode_literals
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.conf import settings
from filebrowser.base import FileListing
from django.core.files.storage import FileSystemStorage
import xml.etree.ElementTree as ET
from Nessus_Parser.models import Hosts
from Nessus_Parser.models import Vulnerability
from Nessus_Map import views as map_views
import json
import os
from io import StringIO
from zipfile import ZipFile
from io import BytesIO

def check_json_exists(request, filename):
    if os.path.exists(settings.JSON_ROOT + '/' + filename):
        return True
    return False

def load_json_dict(filename):
    with open(settings.JSON_ROOT + '/' + filename) as json_file:
        loaded_json = json.load(json_file)
        return loaded_json

def load_json_file(request):
    if request.method == 'POST':
        print(request.POST)
        if 'loadjson' not in request.POST:
            return map_views.home_alert(request, 'Please select JSON type to load')
        if 'load-local' not in request.POST:
            return map_views.home_alert(request, 'Please select Load from local JSON Directory checkbox')
        select_val = request.POST['loadjson']
        if select_val == '1':
            if not check_json_exists(request, 'executive.json'): return map_views.home_alert(request, 'Please create a executive.json file first')
            ex_json = load_json_dict('executive.json')
            return render(request, 'generate_executive.html', {'vulns' : ex_json['vulndict'], 'vulnOrder' : ex_json['sorted_d'], "host_dict": sorted(ex_json['host_dict'].items(), key=lambda value: value[1], reverse=True), "host_vuln_detail" : ex_json['host_vuln_detail']})
        elif select_val == '2':
            if not check_json_exists(request, 'vulns.json'): return map_views.home_alert(request, 'Please create a vulns.json file first')
            vulns = load_json_dict('vulns.json')
            if not 'critical' in request.POST: vulns['Critical'] = ""
            if not 'high' in request.POST: vulns['High'] = ""
            if not 'medium' in request.POST: vulns['Medium'] = ""
            if not 'low' in request.POST: vulns['Low'] = ""
            if not 'info' in request.POST: vulns['None'] = ""
            return render(request, 'parsed_XML.html', {'vulns' : vulns})
        elif select_val == '3':
            if not check_json_exists(request, 'services.json'): return map_views.home_alert(request, 'Please create a services.json file first')
            services = load_json_dict('services.json')
            return render(request, 'port_filter.html', {'services':services})
        elif select_val == '4':
            if not check_json_exists(request, 'osDict.json'): return map_views.home_alert(request, 'Please create a osDict.json file first')
            osDict = load_json_dict('osDict.json')
            return render(request, 'parse_os.html', {'osDict' : osDict})
    # return map_views.home_alert(request, 'abc')
    return redirect('home')

def generate_html_report(request):
    if request.method == 'POST':
        select_val = request.POST["reporttype"]
        print(select_val)
        if select_val == "1":
            return generate_executive_report(request)
        elif select_val == "2":
            return parse_XML(request)
        elif select_val == "3":
            return do_port_filter(request)
        elif select_val == "4":
<<<<<<< HEAD
            return do_parse_host(request)
        elif select_val == "5":
=======
>>>>>>> 85ae870f8c00d7861a2dfa91d85b3294e969c538
            return do_parse_os(request)
        else:
            return redirect('home')
    return redirect('home')

<<<<<<< HEAD
def do_parse_host(request):
    hosts = get_host_parse_json()
    return render(request, 'host_report.html', {'hosts' : hosts})

def get_host_parse_json():
    hosts = dict()
    files = os.listdir(settings.MEDIA_ROOT)
    for file in files:
        path = os.path.join(settings.MEDIA_ROOT, file)
        hosts = do_parse_hosts(hosts, path, file)
    return hosts

def do_parse_hosts(hosts, path, file):
    tree = ET.parse(path)
    for host in tree.findall('Report/ReportHost'):
        ipaddr = host.find("HostProperties/tag/[@name='host-ip']").text
        if ipaddr not in hosts:
            hosts[ipaddr]               = dict()
            hosts[ipaddr]['services']   = list()
            hosts[ipaddr]['vulns']      = list()

        for item in host.findall('ReportItem'):
            vuln        = dict()
            service     = item.get('svc_name')
            port        = item.get('port')
            protocol    = item.get('protocol')
            ipaddr2     = "{0} ({1}/{2})".format(ipaddr, port, protocol)
            if ipaddr2 not in hosts[ipaddr]['services']:
                hosts[ipaddr]['services'].append(ipaddr2)
            # -------- vuln parsing ------
            risk_factor     = item.find('risk_factor').text
            pluginID        = item.get('pluginID')
            pluginName      = item.get('pluginName')
            port            = item.get('port')
            protocol        = item.get('protocol')
            plugin_output   = ""

            if item.find('plugin_output') is not None:
                plugin_output = item.find('plugin_output').text
                        
            vuln['Risk'] = risk_factor
            vuln['ID'] = pluginID
            vuln['Title'] = pluginName
            vuln['Port'] = port
            vuln['Protocol'] = protocol
            vuln['Output'] = plugin_output
            hosts[ipaddr]['vulns'].append(vuln);
    return hosts


=======
>>>>>>> 85ae870f8c00d7861a2dfa91d85b3294e969c538
def download_json_file(json_data, filename):
    response = HttpResponse(json_data, content_type='application/json')
    response['Content-Disposition'] = 'attachment; filename="' + filename + '"'
    return response

def save_json_file(json_data, filename):
    if not os.path.exists(settings.JSON_ROOT):
        os.mkdir(settings.JSON_ROOT)
    with open(settings.JSON_ROOT + '/' + filename, 'w') as file:
        file.write(json.dumps(json_data))
    # os.system("nautilus \"" + settings.JSON_ROOT + "\"")
    print(settings.JSON_ROOT + "/" + filename + " saved ....")

def generate_json_file(request):
    if request.method == 'POST':
        if "genjson" not in request.POST: return redirect('home')
        select_val = request.POST["genjson"]
        download = 0; save = 0
        if "download" in request.POST: download = 1
        if "save" in request.POST: save = 1
        if select_val == '1':
            executive_json = generate_executive_json();
            vulns = parse_all_xml()
            services = parse_services()
            osDict = os_parser()
<<<<<<< HEAD
            hosts = get_host_parse_json()

=======
>>>>>>> 85ae870f8c00d7861a2dfa91d85b3294e969c538
            if save == 1:
                save_json_file(executive_json, "executive.json")
                save_json_file(vulns, "vulns.json")
                save_json_file(services, "services.json")
                save_json_file(osDict, "osDict.json")
<<<<<<< HEAD
                save_json_file(hosts, "hosts.json")

=======
            
>>>>>>> 85ae870f8c00d7861a2dfa91d85b3294e969c538
            if download == 1:
                in_memory = BytesIO()
                zip = ZipFile(in_memory, "w")
                    
                zip.writestr("executive.json", json.dumps(executive_json))
                zip.writestr("vulns.json", json.dumps(vulns))
                zip.writestr("services.json", json.dumps(services))
                zip.writestr("osDict.json", json.dumps(osDict))
<<<<<<< HEAD
                zip.writestr("hosts.json", json.dumps(hosts))
=======
                
>>>>>>> 85ae870f8c00d7861a2dfa91d85b3294e969c538
                # fix for Linux zip files read in Windows
                for file in zip.filelist:
                    file.create_system = 0    
                    
                zip.close()

                response = HttpResponse(content_type="application/zip")
                response["Content-Disposition"] = "attachment; filename=json.zip"
                
                in_memory.seek(0)    
                response.write(in_memory.read())
                
                return response
        elif select_val == '2':
            executive_json = generate_executive_json();
            if save == 1: save_json_file(executive_json, "executive.json")
            if download == 1: return download_json_file(executive_json, "executive.json")
        elif select_val == '3':
            vulns = parse_all_xml()
            if save == 1: save_json_file(vulns, "vulns.json")
            if download == 1: return download_json_file(vulns, "vulns.json")
        elif select_val == '4':
            services = parse_services()
            if save == 1: save_json_file(services, "services.json")
            if download == 1: return download_json_file(services, "services.json")
        elif select_val == '5':
<<<<<<< HEAD
            hosts = get_host_parse_json()
            if save == 1: save_json_file(hosts, "hosts.json")
            if download == 1: return download_json_file(hosts, "hosts.json")
        elif select_val == '6':
=======
>>>>>>> 85ae870f8c00d7861a2dfa91d85b3294e969c538
            osDict = os_parser()
            if save == 1: save_json_file(osDict, "osDict.json")
            if download == 1: return download_json_file(osDict, "osDict.json")
    return redirect('home')

def generate_executive_json():
    vulns = parse_all_xml()
    vulndict = dict()
    hostdict = dict()

    for risk in vulns:
        for vuln in vulns[risk]:
            vulndict[vuln] = dict()
            vulndict[vuln]["risk"] = risk
            vulndict[vuln]["name"] = vulns[risk][vuln]["name"]
            vulndict[vuln]["count"] = len(vulns[risk][vuln]["hosts"])

    sorted_d = sorted(vulndict, key=lambda x:vulndict[x]['count'], reverse=True)
    host_dict = dict()
    host_vuln_detail = dict()
    files = os.listdir(settings.MEDIA_ROOT)

    for file in files:
        path = os.path.join(settings.MEDIA_ROOT, file)
        host_dict, host_vuln_detail = do_host_vuln_parsing(path, host_dict, host_vuln_detail)
    
    ex_json = dict()
    # ex_json['vulns'] = vulns 
    ex_json['vulndict'] = vulndict
    ex_json['sorted_d'] = sorted_d
    # ex_json['hostdict'] = hostdict
    ex_json['host_dict'] = host_dict
    ex_json['host_vuln_detail'] = host_vuln_detail
    return ex_json

def generate_executive_report(request):
    ex_json = generate_executive_json()
    return render(request, 'generate_executive.html', {'vulns' : ex_json['vulndict'], 'vulnOrder' : ex_json['sorted_d'], "host_dict": sorted(ex_json['host_dict'].items(), key=lambda value: value[1], reverse=True), "host_vuln_detail" : ex_json['host_vuln_detail']})

def handle_uploaded_file(myfile):
    with open(settings.MEDIA_ROOT, 'wb+') as destination:
        for chunk in myfile.chunks():
            destination.write(chunk)

def upload_file(request):
    return redirect('home')

def parse_XML(request):
    vulns = parse_all_xml()
    return render(request, 'parsed_XML.html', {'vulns' : vulns})

def parse_all_xml():
    vulns = dict()
    vulns['Critical'] = dict()
    vulns['High'] = dict()
    vulns['Medium'] = dict()
    vulns['Low'] = dict()
    vulns['None'] = dict()
    files = os.listdir(settings.MEDIA_ROOT)
    
    for file in files:
        path = os.path.join(settings.MEDIA_ROOT, file)
        vulns = do_vuln_parsing(vulns, path, file)
    # file = open("nessus.csv", "w")
    # for sev in vulns:
    #     for vuln in vulns[sev]:
    #         ips = ""
    #         for host in vulns[sev][vuln]['hosts']:
    #             ips += host[0] + " "
    #         print(sev+","+vulns[sev][vuln]['name']+","+ips)
    #         file.write(sev+","+vulns[sev][vuln]['name']+","+ips+"\n")
    # file.close()
    return vulns

def do_vuln_parsing(vulns, path, filename):
    tree = ET.parse(path)
    for host in tree.findall('Report/ReportHost'):
        ipaddr = host.find("HostProperties/tag/[@name='host-ip']").text
        for item in host.findall('ReportItem'):
            risk_factor     = item.find('risk_factor').text
            pluginID        = item.get('pluginID')
            pluginName      = item.get('pluginName')
            port            = item.get('port')
            protocol        = item.get('protocol')
           
            plugin_output   = ""
            description     = ""
            synopsis        = ""
            see_also        = ""
            solution        = ""

            if item.find('plugin_output') is not None:
                plugin_output = item.find('plugin_output').text

            if item.find('description') is not None:
                description = item.find('description').text

            if item.find('synopsis') is not None:
                synopsis    = item.find('synopsis').text

            if item.find('see_also') is not None:
                see_also    = item.find('see_also').text

            if item.find('solution') is not None:
                solution    = item.find('solution').text

            ipaddr2 = "{0} ({1}/{2})".format(ipaddr, port, protocol)


            if pluginID in vulns['Critical'] or pluginID in vulns['High'] or pluginID in vulns['Medium'] or pluginID in vulns['Low'] or pluginID in vulns['None']:

                ip_entry_flag = False

                for ip in vulns[risk_factor][pluginID]['hosts']:
                    if ip[0] in ipaddr2:
                        ip_entry_flag = True
                        break

                if not ip_entry_flag:
                    vulns[risk_factor][pluginID]['hosts'].append([ipaddr2, plugin_output])

                if filename not in vulns[risk_factor][pluginID]['file']:
                     vulns[risk_factor][pluginID]['file'].append(filename)
            else:
                vulns[risk_factor][pluginID] = { 
                    'risk':risk_factor,
                    'name' : pluginName,
                    'synopsis': synopsis,
                    'see_also' : see_also,
                    'solution' : solution,
                    'file' : [filename],
                    'hosts' : [[ipaddr2,plugin_output]],
                    'pluginID': pluginID,
                    'description': description
                }
        
            
    return vulns

def do_port_filter(request):
    services = parse_services()
    return render(request, 'port_filter.html', {'services':services})

def parse_services():
    services = dict()
    files = os.listdir(settings.MEDIA_ROOT)
    for file in files:
        path = os.path.join(settings.MEDIA_ROOT, file)
        services = do_parse_services(services, path, file)
    return services

def do_parse_services(services, path, filename):
    tree = ET.parse(path)
    for host in tree.findall('Report/ReportHost'):
        ipaddr = host.find("HostProperties/tag/[@name='host-ip']").text
        for item in host.findall('ReportItem'):
            service = item.get('svc_name')
            port = item.get('port')
            protocol = item.get('protocol')
            ipaddr2 = "{0} ({1}/{2})".format(ipaddr, port, protocol)
            if service in services:
                if ipaddr2 not in services[service]:
                    services[service].append(ipaddr2)
            else:
                services[service] = [ipaddr2]
    return services

def do_parse_os(request):
    osDict = os_parser()
    return render(request, 'parse_os.html', {'osDict' : osDict})
    
def os_parser():
    osDict = dict()
    files = os.listdir(settings.MEDIA_ROOT)
    for file in files:
        path = os.path.join(settings.MEDIA_ROOT, file)
        osDict = do_os_parsing(osDict, path, file)
    return osDict

def do_os_parsing(osDict, path, filename):
    tree = ET.parse(path)
    
    for host in tree.findall('Report/ReportHost'):
        ipaddr = host.find("HostProperties/tag/[@name='host-ip']").text
        
        for item in host.findall('ReportItem'):
            pluginID        = item.get('pluginID')
            
            if pluginID != "33850" and pluginID != "108797" and pluginID != "84729" and pluginID != "97996" and pluginID != "73182" and pluginID != "88561" and pluginID != "108797":
                continue
            plugin_output   = ""
            
            if item.find('plugin_output') is not None:
                plugin_output = item.find('plugin_output').text
            
            if "support ended on" in plugin_output:
                plugin_output = plugin_output.split("support ended on")[0]
            
            if "The following Windows version is installed and not supported:" in plugin_output:
                plugin_output = plugin_output.split("The following Windows version is installed and not supported:")[1]
            osDict[ipaddr] = plugin_output
    
    return osDict

def do_host_vuln_parsing(path, host_dict, host_vuln_detail):
    tree = ET.parse(path)
    
    for host in tree.findall('Report/ReportHost'):
        ipaddr = host.find("HostProperties/tag/[@name='host-ip']").text
        
        if(ipaddr not in host_vuln_detail):
            host_vuln_detail[ipaddr] = dict()
            host_vuln_detail[ipaddr]["Critical"] = 0
            host_vuln_detail[ipaddr]["High"] = 0
            host_vuln_detail[ipaddr]["Medium"] = 0
            host_vuln_detail[ipaddr]["Low"] = 0
            host_vuln_detail[ipaddr]["Info"] = 0
        
        for item in host.findall('ReportItem'):
            risk_factor     = item.find('risk_factor').text
            
            if("Critical" in risk_factor):
                host_vuln_detail[ipaddr]["Critical"] = int(host_vuln_detail[ipaddr]["Critical"]) + 1
            
            elif("High" in risk_factor):
                host_vuln_detail[ipaddr]["High"] = host_vuln_detail[ipaddr]["High"] + 1
            
            elif("Medium" in risk_factor):
                host_vuln_detail[ipaddr]["Medium"] = host_vuln_detail[ipaddr]["Medium"] + 1
            
            elif("Low" in risk_factor):
                host_vuln_detail[ipaddr]["Low"] = host_vuln_detail[ipaddr]["Low"] + 1
            
            elif("None" in risk_factor):
                host_vuln_detail[ipaddr]["Info"] = host_vuln_detail[ipaddr]["Info"] + 1
            
            else:
                print(risk_factor)
        
        host_dict[ipaddr] = int(host_vuln_detail[ipaddr]["Critical"]) + int(host_vuln_detail[ipaddr]["High"]) + int(host_vuln_detail[ipaddr]["Medium"]) + int(host_vuln_detail[ipaddr]["Low"]) + int(host_vuln_detail[ipaddr]["Info"])
        
    return host_dict, host_vuln_detail



