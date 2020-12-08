import re
import sys
import subprocess


def myip():
    if sys.platform in ('linux', 'linux2'):
        conf = subprocess.check_output('ifconfig', shell=True).decode().split('\n\n')[:-1]
        conf_check = list(map(lambda x:
                              re.search(r'[\w.]+\d',
                                        re.search(r'\(.*\)',
                                                  re.search(r'RX packets.*\(.*\)', x)
                                                  .group()).group()).group(), conf))
        interface = conf_check.index(max(conf_check))
        ip = re.search(r'inet \w{1,3}.\w{1,3}.\w{1,3}.\w{1,3}', conf[interface]).group()[5:]
    if sys.platform == 'win32':
        conf = subprocess.check_output('ipconfig', shell=True).decode()
        ip = re.search(r':.*\d', re.search(r'IPv4.*:.*\..*', conf).group()).group()[2:]
    ext_ip = subprocess.Popen('nslookup myip.opendns.com. resolver1.opendns.com',
                              stdout=subprocess.PIPE, shell=True).communicate()[0].decode()
    ext_ip = re.search(r'\w{1,3}\.\w{1,3}\.\w{1,3}\.\w{1,3}[^#\w]', ext_ip).group().rstrip('/n')
    print('[*] Your external ip: ' + ext_ip)
    return ip