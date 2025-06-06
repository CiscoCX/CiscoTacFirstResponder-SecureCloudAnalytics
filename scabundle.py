#!/usr/bin/python3

__author__ = "SCA TAC First Responders"
__copyright__ = "Copyright 2023, Cisco Systems Inc."
__version__ = "1.2.4"
__status__ = "Production"

import netifaces
import logging
import os
import subprocess
import tempfile
import requests
from argparse import ArgumentParser
from datetime import datetime, timezone
from os import mkdir, path
from shutil import copy, copytree, ignore_patterns
from subprocess import STDOUT, CalledProcessError, TimeoutExpired, check_output, run

try:
    import requests
    rqst_avail = True
except ImportError:
    rqst_avail = False

parser = ArgumentParser()
subparsers = parser.add_subparsers(dest="command", required=True)
parser_upload = subparsers.add_parser("upload")
parser_upload.add_argument("-c", "--case", help="The case number to attach the files to", required=True)
parser_upload.add_argument("-t", "--token", help="The token to upload files to cxd.cisco.com", required=True)
parser_no_upload = subparsers.add_parser("no-upload")
args = parser.parse_args()
if args.command == "upload":
    case = str(args.case)
    token = str(args.token)

if args.command == "no-upload":
    pass

def create_bundle_dir():
    temp_dir = tempfile.mkdtemp()
    return temp_dir

bundledir = create_bundle_dir()

def set_stage():
    for subdir in "ona_meta_data", "os_info", "network", "connectivity", "process_info", "disk_stats":
        mkdir(path.join(bundledir, subdir))

def root_check():
    return os.geteuid() == 0

def print_log(msg, screen=False, log=False, color=None, level='info'):
    if screen:
        color_code = {'red': '\033[91m', 'green': '\033[92m'}.get(color, '')
        print(f'{color_code}{msg} \033[00m' if color_code else msg)
    if log:
        logging_func = getattr(logging, level)
        logging_func(msg)

def upload_file(case, token, f_name):
    if rqst_avail:
        try:
            with open(f_name, "rb") as data:
                response = requests.put(f"https://cxd.cisco.com/home/{f_name}", data=data, auth=requests.auth.HTTPBasicAuth(case, token), headers={"accept": "application/json"})
                response.raise_for_status()
                print_log(f"`{f_name}` successfully uploaded to {case}", screen=True, log=True, color="green", level="info")
        except requests.HTTPError as rqst_err:
            print_log(f"[FAILURE] Failed to upload Failed to upload `{f_name}` to {case} with token {token} using requests.", screen=True, color="red" )
            print_log(f"Upload Failed with the following HTTP error:\n----------\n{rqst_err}\n----------", log=True, level="warning" )
            exit()
        except FileNotFoundError as file_err:
            print_log(f"[FAILURE] Failed to upload `{f_name}` to {case} with token {token}.", screen=True, log=True, color="red", level="warning")
            exit()
    else:
        command = ["curl","-k","--progress-bar",f"https://{case}:{token}@cxd.cisco.com/home/","--upload-file"]
        try:
            output = subprocess.check_output(command)
            if output:
                print_log(f"[FAILURE] (cURL) Failed to upload `{f_name}` to {case} with token {token} using cURL.", screen=True, color="red")
                print_log(f"(cURL) Upload Failed with the following curl error:\n----------\n{output}\n----------", log=True, level="warning")
                exit()
            print_log(f"(cURL) `{f_name}` successfully uploaded to {case} with token {token}.", screen=True, log=True, color="green", level="info")
        except subprocess.CalledProcessError as e:
            print_log(f"[FAILURE] Failed to upload `{f_name}` to {case} with token {token} using cURL.", screen=True, color="red")
            print_log(f"Upload failed with the following subprocess error:\n----------\n{e}\n----------", log=True, level="warning")
            print_log("Notify Cisco TAC of Failure to upload for further assistance", log=True, level="warning")
            exit()


def cmd_to_file(filename, command):
    try: result = check_output(command, timeout=10, stderr=STDOUT, shell=True)
    except (CalledProcessError, TimeoutExpired) as e: result = e.output
    with open(filename, 'w') as f: print(f"{result.decode('utf8')}", file=f, end='')

def get_ip():
    for interface in netifaces.interfaces():
        if interface.startswith('lo'): continue
        addresses = netifaces.ifaddresses(interface).get(netifaces.AF_INET)
        if addresses:
            ip_address = addresses[0]['addr']
            with open(f'{bundledir}/ona_meta_data/mgmt_ip', 'w') as f:
                f.write(ip_address)
            return ip_address
    return None

def ona_meta_data():
    cmd_to_file(f'{bundledir}/ona_meta_data/version', 'cat /opt/obsrvbl-ona/version')
    cmd_to_file(f'{bundledir}/ona_meta_data/hostname', 'hostname --long')
    cmd_to_file(f'{bundledir}/ona_meta_data/platform', 'cat /sys/class/dmi/id/product_name')
    cmd_to_file(f'{bundledir}/ona_meta_data/serial', 'cat /sys/class/dmi/id/product_serial | tr -sd " "')

def os_info():
    cmd_to_file(f'{bundledir}/os_info/uname', 'uname -a')
    cmd_to_file(f'{bundledir}/os_info/sysctl', 'sysctl -a')
    cmd_to_file(f'{bundledir}/os_info/release', 'lsb_release -a 2>/dev/null')
    cmd_to_file(f'{bundledir}/os_info/os_release', 'cat /etc/os-release')
    cmd_to_file(f'{bundledir}/os_info/bash_history', 'head -n0 /home/*/.bash_history')
    cmd_to_file(f'{bundledir}/os_info/dpkg_ona', 'dpkg-query -W ona-service')
    cmd_to_file(f'{bundledir}/os_info/apt_list_ona', 'apt list --installed ona-service')
    cmd_to_file(f'{bundledir}/os_info/rpm_ona', 'rpm -q ona-service')
    cmd_to_file(f'{bundledir}/os_info/dpkg_netsa', 'dpkg-query -W netsa-pkg')
    cmd_to_file(f'{bundledir}/os_info/apt_list_netsa', 'apt list --installed netsa-pkg')
    cmd_to_file(f'{bundledir}/os_info/rpm_netsa', 'rpm -q netsa-pkg')
    cmd_to_file(f'{bundledir}/os_info/last_reboot', 'uptime -s')
    cmd_to_file(f'{bundledir}/os_info/all_installed_packages', 'apt list --installed')

def network():
    cmd_to_file(f'{bundledir}/network/ip_addr_show', 'ip addr show')
    cmd_to_file(f'{bundledir}/network/netstat_tunap', 'netstat -tunap')
    cmd_to_file(f'{bundledir}/network/route', 'route -n')
    cmd_to_file(f'{bundledir}/network/ifconfig', 'ifconfig -a')

def connectivity():
    cmd_to_file(f'{bundledir}/connectivity/resolv', 'grep -Ev "^#" /etc/resolv.conf')
    cmd_to_file(f'{bundledir}/connectivity/netplan', 'cat /etc/netplan/*.yaml')
    cmd_to_file(f'{bundledir}/connectivity/timedatectl', 'timedatectl')
    cmd_to_file(f'{bundledir}/connectivity/chrony', 'cat /etc/chrony.conf')
    cmd_to_file(f'{bundledir}/connectivity/ntp', 'cat /etc/ntp.conf')
    cmd_to_file(f'{bundledir}/connectivity/sensor_ext', 'curl -so- -D- --connect-timeout 5 https://sensor.ext.obsrvbl.com')
    cmd_to_file(f'{bundledir}/connectivity/sensor_us', 'curl -so- -D- --connect-timeout 5 https://sensor.obsrvbl.obsrvbl.com')
    cmd_to_file(f'{bundledir}/connectivity/sensor_eu', 'curl -so- -D- --connect-timeout 5 https://sensor.eu-prod.obsrvbl.com')
    cmd_to_file(f'{bundledir}/connectivity/sensor_anz', 'curl -so- -D- --connect-timeout 5 https://sensor.anz-prod.obsrvbl.com')
    cmd_to_file(f'{bundledir}/connectivity/iptables', 'iptables -nvL')
    cmd_to_file(f'{bundledir}/connectivity/firewalld', 'firewall-cmd --list-all-zones')

def ona_settings_and_logs():
    copytree("/opt/obsrvbl-ona/", f'{bundledir}/ona_settings/', ignore=ignore_patterns('*python-packages*', '*__pycache__*','*.2*','*pna-*.log*','*pdns_*.pcap.gz'), copy_function=copy)
    copytree("/var/log", f'{bundledir}/var/log/', ignore=ignore_patterns('*.dat','journal'), copy_function=copy)
    if os.path.exists("/etc/ise_poller"):
        copytree("/etc/ise_poller", f'{bundledir}/etc/ise_poller/', copy_function=copy)
    if os.path.exists("/tmp/ise_poller"):
        copytree("/tmp/ise_poller", f'{bundledir}/tmp/ise_poller/', copy_function=copy)
    cmd = f"/opt/silk/bin/rwcut --timestamp-format iso --fields sIp,dIp,sPort,dPort,protocol,Bytes,Packets,sTime,eTime /opt/obsrvbl-ona/logs/ipfix/.202* >> {bundledir}/ona_settings/logs/ipfix/clear_silk 2>/dev/null"
    run(cmd,shell=True)

def process_info():
    cmd_to_file(f'{bundledir}/process_info/top', 'top -bn1')
    cmd_to_file(f'{bundledir}/process_info/free', 'free -m')
    cmd_to_file(f'{bundledir}/process_info/meminfo', 'cat /proc/meminfo')
    cmd_to_file(f'{bundledir}/process_info/cpuinfo', 'cat /proc/cpuinfo')
    cmd_to_file(f'{bundledir}/process_info/ps_faux', 'ps faux')
    cmd_to_file(f'{bundledir}/process_info/ps_obsrvbl', 'ps -fU obsrvbl_ona')

def disk_stats():
    cmd_to_file(f'{bundledir}/disk_stats/df_ah', 'df -ah')
    cmd_to_file(f'{bundledir}/disk_stats/du_xah', 'du -xah /')
    cmd_to_file(f'{bundledir}/disk_stats/mounts', 'cat /proc/mounts')
    cmd_to_file(f'{bundledir}/disk_stats/vgdisplay', 'vgdisplay')
    cmd_to_file(f'{bundledir}/disk_stats/lvdisplay', 'lvdisplay')
    cmd_to_file(f'{bundledir}/disk_stats/lsblk', 'lsblk')
    cmd_to_file(f'{bundledir}/disk_stats/allfiles-list', 'ls -laR /opt/ /etc/ /tmp/')
    cmd_to_file(f'{bundledir}/lsof', 'timeout 60 lsof')

def pcap_30_second():
    cmd = f"timeout 30 tcpdump -i any not host localhost and not host 127.0.0.1 and udp -c10000 -w {bundledir}/capture.pcap >/dev/null 2>&1"
    run(cmd, shell=True)

def main():
    functions = [set_stage, ona_meta_data, get_ip, os_info, network, connectivity, ona_settings_and_logs, process_info, disk_stats, pcap_30_second]
    print("\r\n*** Creating Support Bundle")
    for i, func in enumerate(functions, start=1):
        print(f"Processing {i}/{len(functions)}: {func.__name__:<22}", end="\r")
        func()
    bundle_name = f"scabundle-ona-{open('/sys/class/dmi/id/product_serial').read().strip().replace(' ','')}.{datetime.now(timezone.utc).strftime('%Y%m%d.%H%M')}"
    if args.command == "upload":
        bundle_name += "_xdrafr.tar.xz"
    else:
        bundle_name += ".tar.xz"
    cmd = f"tar -Jcf {bundle_name} -C {bundledir} . ../capture.pcap --remove-files 2>/dev/null"
    print("\nCompressing files. This may take some time.")
    run(cmd, shell=True)

    if args.command == "upload":
        print("\nUploading file to TAC Case. This may take some time.")
        upload_file(case, token, bundle_name)
    else:
        pass

if root_check():
    main()
else:
    print("You are not root, re-run this script as root. Exiting.")
