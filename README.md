Cisco TAC First Responder script for Secure Cloud Analytics.

This hosted script aids in the generation, compression, and trannsmission of a Secure Cloud Analytics bundle from an Obsrvbl Network Appliance (ONA) On-Prem Sensor. 
It should be noted that the script was designed around the provided ONA image obtained in the SCA portal that is Debian based. 
Efforts have been made to work for advanced installations (non-default) Linux distros such as Red Hat, CentOS, etc. 

Example output:

sysadmin@ona-12a345:~$ sudo python3 scabundle.py -c 611111111 -t mkFAKEk2Y12345yuEkz

*** Creating Support Bundle
Processing 9/9: pcap_30_second
Compressing files. This may take some time.
##################################################################################################################################################################################################### 100.0%
`scabundle-ona-VMware-123a4bc56defgh78-9876zyx543219876.20230626.1652.tar.xz` successfully uploaded to 611111111
sysadmin@ona-12a345:~$

If you do not run script as root / sudo, the script will error out. 
Example output: 

sysadmin@ona-12a345:~$ python3 scabundle.py -c 611111111 -t mkFAKEk2Y12345yuEkz
You are not root, re-run this script as root. Exiting.
sysadmin@ona-12a345:~$ 
