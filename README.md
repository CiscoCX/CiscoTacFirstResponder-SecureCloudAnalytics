Cisco TAC First Responder script for Secure Cloud Analytics.

This hosted script aids in the generation, compression, and trannsmission of a Secure Cloud Analytics bundle from an Obsrvbl Network Appliance (ONA) On-Prem Sensor. 
It should be noted that the script was designed around the provided ONA image obtained in the SCA portal that is Debian based. 
Efforts have been made to work for advanced installations (non-default) Linux distros such as Red Hat, CentOS, etc. 

Example output:
```
sysadmin@ona-12a345:~$ curl -s https://raw.githubusercontent.com/CiscoCX/CiscoTacFirstResponder-SecureCloudAnalytics/main/scabundle.py | sudo python3 - -c 611111111 -t mkFAKEk2Y12345yuEkz
[sudo] password for sysadmin:

*** Creating Support Bundle
Processing 9/9: pcap_30_second
Compressing files. This may take some time.

Uploading file to TAC Case. This may take some time.
######################################################################## 100.0%
`scabundle-ona-VMware-564d5da42dfcca70-8150ada109859521.20230626.1757.tar.xz` successfully uploaded to 695575321
sysadmin@ona-12a345:~$
```

If you do not run script as root / sudo, the script will error out. 
Example output: 
```
sysadmin@ona-12a345:~$ curl https://raw.githubusercontent.com/CiscoCX/CiscoTacFirstResponder-SecureCloudAnalytics/main/scabundle.py | python3 - -c 611111111 -t mkFAKEk2Y12345yuEkz
You are not root, re-run this script as root. Exiting.
sysadmin@ona-12a345:~$
```
