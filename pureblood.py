#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Script Created By:
    Cr4sHCoD3
Page:
    https://github.com/cr4shcod3
    https://github.com/cr4shcod3/pureblood
FB Page:
    https://facebook.com/cr4shcod3.py
Copyrights:
    Cr4sHCoD3 2018
    MIT LICENSE
Special Mentions:
    PureHackers PH
    Blood Security Hackers
"""




import os
import sys
import platform
import time
import datetime
import re
import threading
import socket
import webbrowser



try:
    import colorama
    colorama.init()
except:
    print ('[!] - Module (colorama) not installed!')



try:
    import requests
    from requests.exceptions import ConnectionError
except:
    print ('[!] - Module (requests) not installed!')



try:
    import whois
except:
    print ('[!] - Module (python-whois) not installed!')



try:
    import dns.resolver
except:
    print ('[!] - Module (dnspython) not installed!')



try:
    from bs4 import BeautifulSoup
except:
    print ('[!] - Module (bs4) not installed!')



#########################################################################################################################################################
# GLOBAL

## Color
reset = '\033[0m'
bold = '\033[1m'
underline = '\033[4m'
### Fore
black = '\033[90m'; red = '\033[91m'; green = '\033[92m'; yellow = '\033[93m'; blue = '\033[94m'; magenta = '\033[95m'; cyan = '\033[96m'; white = '\033[97m'
### Background
bg_black = '\033[90m'; bg_red = '\033[91m'; bg_green = '\033[92m'; bg_yellow = '\033[93m'; bg_blue = '\033[94m'; bg_magenta = '\033[95m'; bg_cyan = '\033[96m'; bg_white = '\033[97m'

## Configuration
if platform.system() == 'Windows':
    from ctypes import windll, create_string_buffer
    h = windll.kernel32.GetStdHandle(-12)
    csbi = create_string_buffer(22)
    res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
    if res:
        import struct
        (bufx, bufy, curx, cury, wattr,
        left, top, right, bottom, maxx, maxy) = struct.unpack("hhhhHhhhhhh", csbi.raw)
        sizex = right - left + 1
        sizey = bottom - top + 1
    else:
        sizex, sizey = 80, 25
elif platform.system() == 'Linux':
    sizey, sizex = os.popen('stty size', 'r').read().split()

## Date Time
month = datetime.date.today().strftime("%B")
if datetime.date.today().strftime("%w") == 1 or datetime.date.today().strftime("%w") == '1':
    day = 'Monday'
elif datetime.date.today().strftime("%w") == 2 or datetime.date.today().strftime("%w") == '2':
    day = 'Tuesay'
elif datetime.date.today().strftime("%w") == 3 or datetime.date.today().strftime("%w") == '3':
    day = 'Wednesday'
elif datetime.date.today().strftime("%w") == 4 or datetime.date.today().strftime("%w") == '4':
    day = 'Thursday'
elif datetime.date.today().strftime("%w") == 5 or datetime.date.today().strftime("%w") == '5':
    day = 'Friday'
elif datetime.date.today().strftime("%w") == 6 or datetime.date.today().strftime("%w") == '6':
    day = 'Saturday'
elif datetime.date.today().strftime("%w") == 7 or datetime.date.today().strftime("%w") == '0':
    day = 'Sunday'
mday = datetime.date.today().strftime("%d")
year = datetime.date.today().strftime("%Y")
current_datetime = datetime.datetime.now()
current_time = current_datetime.strftime('%I:%M:%S')

## List
ids = [
    'NONE','A','NS','MD','MF','CNAME','SOA','MB','MG','MR','NULL','WKS','PTR','HINFO','MINFO','MX','TXT','RP','AFSDB','X25','ISDN','RT','NSAP','NSAP-PTR','SIG','KEY','PX','GPOS','AAAA','LOC','NXT','SRV','NAPTR','KX','CERT','A6','DNAME','OPT','APL','DS','SSHFP','IPSECKEY','RRSIG','NSEC','DNSKEY','DHCID','NSEC3','NSEC3PARAM','TLSA','HIP','CDS','CDNSKEY','CSYNC','SPF','UNSPEC','EUI48','EUI64','TKEY','TSIG','IXFR','AXFR','MAILB','MAILA','ANY','URI','CAA','TA','DLV'
]
admin_panel_list = ['/admin.aspx','/admin.asp','/admin.php','/admin/','/administrator/','/moderator/','/webadmin/','/adminarea/','/bb-admin/','/adminLogin/','/admin_area/','/panel-administracion/','/instadmin/','/memberadmin/','/administratorlogin/','/adm/','/admin/account.php','/admin/index.php','/admin/login.php','/admin/admin.php','/admin/account.php','/joomla/administrator','/login.php','/admin_area/admin.php','/admin_area/login.php','/siteadmin/login.php','/siteadmin/index.php','/siteadmin/login.html','/admin/account.html','/admin/index.html','/admin/login.html','/admin/admin.html','/admin_area/index.php','/bb-admin/index.php','/bb-admin/login.php','/bb-admin/admin.php','/admin/home.php','/admin_area/login.html','/admin_area/index.html','/admin/controlpanel.php','/admincp/index.asp','/admincp/login.asp','/admincp/index.html','/admin/account.html','/adminpanel.html','/webadmin.html','webadmin/index.html','/webadmin/admin.html','/webadmin/login.html','/admin/admin_login.html','/admin_login.html','/panel-administracion/login.html','/admin/cp.php','cp.php','/administrator/index.php','/administrator/login.php','/nsw/admin/login.php','/webadmin/login.php','/admin/admin_login.php','/admin_login.php','/administrator/account.php','/administrator.php','/admin_area/admin.html','/pages/admin/admin-login.php','/admin/admin-login.php','/admin-login.php','/bb-admin/index.html','/bb-admin/login.html','/bb-admin/admin.html','/admin/home.html','/modelsearch/login.php','/moderator.php','/moderator/login.php','/moderator/admin.php','/account.php','/pages/admin/admin-login.html','/admin/admin-login.html','/admin-login.html','/controlpanel.php','/admincontrol.php','/admin/adminLogin.html','/adminLogin.html','/admin/adminLogin.html','/home.html','/rcjakar/admin/login.php','/adminarea/index.html','/adminarea/admin.html','/webadmin.php','/webadmin/index.php','/webadmin/admin.php','/admin/controlpanel.html','/admin.html','/admin/cp.html','cp.html','/adminpanel.php','/moderator.html','/administrator/index.html','/administrator/login.html','/user.html','/administrator/account.html','/administrator.html','/login.html','/modelsearch/login.html','/moderator/login.html','/adminarea/login.html','/panel-administracion/index.html','/panel-administracion/admin.html','/modelsearch/index.html','/modelsearch/admin.html','/admincontrol/login.html','/adm/index.html','/adm.html','/moderator/admin.html','/user.php','/account.html','/controlpanel.html','/admincontrol.html','/panel-administracion/login.php','/wp-login.php','/adminLogin.php','/admin/adminLogin.php','/home.php','/adminarea/index.php','/adminarea/admin.php','/adminarea/login.php','/panel-administracion/index.php','/panel-administracion/admin.php','/modelsearch/index.php','/modelsearch/admin.php','/admincontrol/login.php','/adm/admloginuser.php','/admloginuser.php','/admin2.php','/admin2/login.php','/admin2/index.php','adm/index.php','adm.php','affiliate.php','/adm_auth.php  ','/memberadmin.php','/administratorlogin.php','/login/admin.asp','/admin/login.asp','/administratorlogin.asp','/login/asmindstrator.asp','/admin/login.aspx','/login/admin.aspx','/administartorlogin.aspx','login/administrator.aspx','/adminlogin.asp','a/dminlogin.aspx','/admin_login.asp','/admin_login.aspx','/adminhome.asp','/adminhome.aspx''/administrator_login.asp','/administrator_login.aspx']
admin_panel_valid = []

## Threading Obejct Funtions
def TCP_connect(ip, port_number, delay, output):
    TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    TCPsock.settimeout(delay)
    try:
        TCPsock.connect((ip, port_number))
        output[port_number] = 'Open'
    except:
        output[port_number] = ''

def subdomain_scanner(subdomain, so_200, so_301, so_302, so_403):
    subdomain = 'http://' + subdomain
    try:
        subdomain_scanner_request = requests.get(subdomain)
        subdomain_scanner_code = subdomain_scanner_request.status_code
        if subdomain_scanner_code == 200:
            so_200.append(subdomain)
        elif subdomain_scanner_code == 301:
            so_301.append(subdomain)
        elif subdomain_scanner_code == 302:
            so_302.append(subdomain)
        elif subdomain_scanner_code == 403:
            so_403.append(subdomain)
    except ConnectionError:
        pass
# END GLOBAL
#########################################################################################################################################################

class Generator:
    def deface_page(self, title, shortcut_icon, meta_description, meta_image, logo, hacker_name, message1, message2, groups):
        deface_page_template = '''
<html>
<head>
  <title>--=[ Hacked By {0} ]=--</title>
  <meta charset=\"UTF-8\">
  <link rel=\"SHORTCUT ICON\" href=\"{1}\">
  <meta name=\"Author\" content=\"Cr4sHCoD3 | PureHackers x Blood Security Hackers\"/>
  <meta name=\"copyright\" content=\"PureHackers | Blood Security Hackers\"/>
  <meta name=\"description\" content=\"{2}.\"/> <!-- Change this -->
  <meta name=\"keywords\" content=\"Hacked, Pawned, Defaced, Security, PureHackers, Blood Security Hackers, PureBlood, Cr4sHCoD3\"/> <!-- Change this -->
  <meta property=\"og:title\" content=\"Hacked By {0}\"/>
  <meta property=\"og:image\" content=\"{3}\"> <!-- Change this -->

  <style>
  {9} url(\"https://cr4shcod3.github.io/python/pureblood/pureblood.css\");
  </style>
</head>
<body>
  <div class=\"bg\">
    <center>
      <img src=\"{4}\" class=\"logo\"/> <!-- Change This -->
      <h1 class=\"header glitch\" data-text=\"Hacked By {5}\">Hacked By {5}</h1><br><br>
      <p class=\"message\">{6}</p>
      <p class=\"message\">{7}</p><br><br>
      <p class=\"groups\">Greetings: {8}</p>
    </center>
  </div>
</body>
</html>
'''.format(title, shortcut_icon, meta_description, meta_image, logo, hacker_name, message1, message2, groups, '@import')
        self.deface_page_result = deface_page_template
        return self.deface_page_result



class WebPentest:
    def banner_grab(self, bg_url):
        banner_grab_request = requests.get(bg_url)
        banner_grab_result = banner_grab_request.headers
        banner_grab_result = str(banner_grab_result).replace("{'", "").replace("'}", "").replace("': '", ": ").replace("', '", ",\n")
        self.banner_grab_result = banner_grab_result
        return self.banner_grab_result

    def whois(self, w_url):
        whois_query = whois.whois(w_url)
        self.whois_result = whois_query
        return self.whois_result

    def traceroute(self, t_hostname):
        traceroute_request = requests.get('https://api.hackertarget.com/mtr/?q=' + t_hostname)
        traceroute_response = traceroute_request.text
        traceroute_final = """{0}""".format(str(traceroute_response))
        self.traceroute_result = traceroute_final
        return self.traceroute_result

    def dns_record(self, dr_hostname):
        dns_record_list = []
        for a in ids:
            try:
                answers = dns.resolver.query(dr_hostname, a)
                for rdata in answers:
                    a = str(a); rdata = str(rdata)
                    dns_record_list.append(str(a + ' : ' + rdata))
            except Exception:
                pass
        self.dns_record_result = dns_record_list
        return self.dns_record_result

    def reverse_dns_lookup(self, rdl_ip):
        rdl_ip = rdl_ip + '/24'
        reverse_dns_lookup_request = requests.get('https://api.hackertarget.com/reversedns/?q=' + rdl_ip)
        reverse_dns_lookup_response = reverse_dns_lookup_request.text
        reverse_dns_lookup_final = """{0}""".format(str(reverse_dns_lookup_response))
        self.reverse_ip_lookup_result = reverse_dns_lookup_final
        return self.reverse_ip_lookup_result

    def zone_transfer_lookup(self, ztl_hostname):
        zone_transfer_lookup_request = requests.get('https://api.hackertarget.com/zonetransfer/?q=' + ztl_hostname)
        zone_transfer_lookup_response = zone_transfer_lookup_request.text
        zone_transfer_lookup_final = """{0}""".format(str(zone_transfer_lookup_response))
        self.zone_transfer_lookup_result = zone_transfer_lookup_final
        return self.zone_transfer_lookup_result

    def port_scan(self, ps_hostname, ps_pend): #https://stackoverflow.com/a/38210023
        port_scan_list = []
        threads = []
        output = {}
        delay = 10
        for i in range(ps_pend + 1):
            t = threading.Thread(target=TCP_connect, args=(ps_hostname, i, delay, output))
            threads.append(t)
        for i in range(ps_pend + 1):
            threads[i].start()
        for i in range(ps_pend + 1):
            threads[i].join()
        for i in range(ps_pend + 1):
            if output[i] == 'Open':
                port_scan_list.append('[+] Port Open - ' + str(i))
        self.port_scan_result = port_scan_list
        return self.port_scan_result

    def admin_panel_scan(self, ads_url):
        admin_panel_valid = []
        admin_panel_redirect = []
        ads_urls = []
        r_path = []
        ads_r_urls = []
        robots = ['/robot.txt', '/robots.txt']
        for i in admin_panel_list:
            ads_urls.append(ads_url + i)
        for i in robots:
            r_robots = requests.get(ads_url + i)
            if r_robots.status_code == 200:
                r_robots = r_robots
            else:
                r_robots = ''
        if r_robots == '':
            pass
        else:
            robots = str(r_robots.text)
            for i in robots.split("\n"):
                if i.startswith('Allow'):
                    r_path.append(i.split(': ')[1].split(' ')[0])
                elif i.startswith('Disallow'):
                    r_path.append(i.split(': ')[1].split(' ')[0])
            for i in r_path:
                ads_r_urls.append(ads_url + i)
        for i in ads_r_urls:
            ads_r_urls_request = requests.get(i)
            if 'Admin' in ads_r_urls_request.text or 'Login' in ads_r_urls_request.text:
                r_admin_panel = i
                admin_panel_valid.append(i)
            elif 'admin' in ads_r_urls_request.text or 'login' in ads_r_urls_request.text:
                r_admin_panel = i
                admin_panel_valid.append(i)
            elif 'Username' in ads_r_urls_request.text or 'Password' in ads_r_urls_request.text:
                r_admin_panel = i
                admin_panel_valid.append(i)
            elif 'username' in ads_r_urls_request.text or 'password' in ads_r_urls_request.text:
                r_admin_panel = i
                admin_panel_valid.append(i)
            else:
                r_admin_panel = None
        if not admin_panel_valid:
            for i in ads_urls:
                admin_scan_request = requests.get(i)
                if admin_scan_request.status_code == 200:
                    admin_panel_valid.append(i)
                    break
                elif admin_scan_request.status_code == 403:
                    admin_panel_redirect.append(i)
        else:
            pass
        admin_panel_valid = list(set(admin_panel_valid))
        for i in admin_panel_redirect:
            admin_panel_valid.append(i + ' - 403')
        if not admin_panel_valid:
            webbrowser.open_new_tab(google_hacking + 'site:' + ads_url + '+inurl:login | admin | user | cpanel | account | moderator | phpmyadmin | /cp')
        self.admin_panel_scan_result = admin_panel_valid
        return self.admin_panel_scan_result

    def subdomain_scan(self, ss_hostname, subdomain_list):
        so_200 = []
        so_301 = []
        so_302 = []
        so_403 = []
        ss_urls = []
        ss_subdomain_list = open(subdomain_list, 'r')
        ss_subdomain_list = ss_subdomain_list.read().splitlines()
        for i in ss_subdomain_list:
            ss_urls.append(i + '.' + ss_hostname)
        for i in ss_urls:
            t = threading.Thread(target=subdomain_scanner, args=(i, so_200, so_301, so_302, so_403,))
            t.start()
        t.join()
        self.ss_200_result = so_200
        self.ss_301_result = so_301
        self.ss_302_result = so_302
        self.ss_403_result = so_403
        return self.ss_200_result, self.ss_301_result, self.ss_302_result, self.ss_403_result

    def cms_detect(self, cd_hostname):
        cd_cms = []
        cd_cms_version = []
        cms_detect_request = requests.get('https://whatcms.org/?s=' + cd_hostname)
        cd_soup = BeautifulSoup(cms_detect_request.content, 'html.parser')
        cd_soup_div = cd_soup.find('div', attrs={'class': 'large text-center'})
        for i in cd_soup_div.find_all('span', attrs={'class': 'nowrap'}):
            cd_cms_version.append(i.text)
        cd_cms.append(cd_soup_div.find('a').text)
        if not cd_cms:
            cms_detect_final = '[!] - There\'s no CMS Detected!'
        else:
            cd_cms_version = cd_cms_version[1]
            cms_detect_final = cd_cms[0].replace('/c/', '')
            cms_detect_final = cms_detect_final + ' - ' + cd_cms_version
        self.cms_detect_result = cms_detect_final
        return self.cms_detect_result

    def reverse_ip_lookup(self, ril_hostname):
        reverse_ip_lookup_request = requests.get('https://api.hackertarget.com/reverseiplookup/?q=' + ril_hostname)
        reverse_ip_lookup_response = reverse_ip_lookup_request.text
        reverse_ip_lookup_final = """{0}""".format(str(reverse_ip_lookup_response))
        self.reverse_ip_lookup_result = reverse_ip_lookup_final
        return self.reverse_ip_lookup_result

    def subnet_lookup(self, subnet_input):
        subnet_lookup_request = requests.get('https://api.hackertarget.com/subnetcalc/?q=' + subnet_input)
        subnet_lookup_response = subnet_lookup_request.text
        subnet_lookup_final = """{0}""".format(str(subnet_lookup_response))
        self.subnet_lookup_result = subnet_lookup_final
        return self.subnet_lookup_result

    def links_extract(self, le_url):
        links_extract_request = requests.get('https://api.hackertarget.com/pagelinks/?q=' + le_url)
        links_extract_response = links_extract_request.text
        links_extract_final = """{0}""".format(str(links_extract_response))
        self.links_extract_result = links_extract_final
        return self.links_extract_result



def clear():
    if platform.system() == 'Linux':
        os.system('clear')
    elif platform.system() == 'Windows':
        os.system('cls')
    elif platform.system() == 'Darwin':
        os.system('clear')
    else:
        os.system('clear')



def banner():
    if sys.version_info[0] == 3:
        banner = ("""{1}
 ██▓███   █    ██  ██▀███  ▓█████     ▄▄▄▄    ██▓     ▒█████   ▒█████  ▓█████▄
▓██░  ██▒ ██  ▓██▒▓██ ▒ ██▒▓█   ▀    ▓█████▄ ▓██▒    ▒██▒  ██▒▒██▒  ██▒▒██▀ ██▌
▓██░ ██▓▒▓██  ▒██░▓██ ░▄█ ▒▒███      ▒██▒ ▄██▒██░    ▒██░  ██▒▒██░  ██▒░██   █▌
▒██▄█▓▒ ▒▓▓█  ░██░▒██▀▀█▄  ▒▓█  ▄    ▒██░█▀  ▒██░    ▒██   ██░▒██   ██░░▓█▄   ▌
▒██▒ ░  ░▒▒█████▓ ░██▓ ▒██▒░▒████▒   ░▓█  ▀█▓░██████▒░ ████▓▒░░ ████▓▒░░▒████▓
▒▓▒░ ░  ░░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░░░ ▒░ ░   ░▒▓███▀▒░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒░▒░▒░  ▒▒▓  ▒
░▒ ░     ░░▒░ ░ ░   ░▒ ░ ▒░ ░ ░  ░   ▒░▒   ░ ░ ░ ▒  ░  ░ ▒ ▒░   ░ ▒ ▒░  ░ ▒  ▒
░░        ░░░ ░ ░   ░░   ░    ░       ░    ░   ░ ░   ░ ░ ░ ▒  ░ ░ ░ ▒   ░ ░  ░
            ░        ░        ░  ░    ░          ░  ░    ░ ░      ░ ░     ░

     {2}--={3}[ {0}{5}Author: Cr4sHCoD3                     {3}]{2}=--
{4}| {2}-- --={3}[ {0}{5}Version: 1                            {3}]{2}=-- -- {4}|
| {2}-- --={3}[ {0}{5}Website: https://github.com/cr4shcod3 {3}]{2}=-- -- {4}|
| {2}-- --={3}[ {0}{5}PureHackers ~ Blood Security Hackers  {3}]{2}=-- -- {4}|
{0}""".format(reset, red, green, blue, yellow, bold))
    elif sys.version_info[0] == 2:
        banner = ("""{1}
 ██▓███   █    ██  ██▀███  ▓█████     ▄▄▄▄    ██▓     ▒█████   ▒█████  ▓█████▄
▓██░  ██▒ ██  ▓██▒▓██ ▒ ██▒▓█   ▀    ▓█████▄ ▓██▒    ▒██▒  ██▒▒██▒  ██▒▒██▀ ██▌
▓██░ ██▓▒▓██  ▒██░▓██ ░▄█ ▒▒███      ▒██▒ ▄██▒██░    ▒██░  ██▒▒██░  ██▒░██   █▌
▒██▄█▓▒ ▒▓▓█  ░██░▒██▀▀█▄  ▒▓█  ▄    ▒██░█▀  ▒██░    ▒██   ██░▒██   ██░░▓█▄   ▌
▒██▒ ░  ░▒▒█████▓ ░██▓ ▒██▒░▒████▒   ░▓█  ▀█▓░██████▒░ ████▓▒░░ ████▓▒░░▒████▓
▒▓▒░ ░  ░░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░░░ ▒░ ░   ░▒▓███▀▒░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒░▒░▒░  ▒▒▓  ▒
░▒ ░     ░░▒░ ░ ░   ░▒ ░ ▒░ ░ ░  ░   ▒░▒   ░ ░ ░ ▒  ░  ░ ▒ ▒░   ░ ▒ ▒░  ░ ▒  ▒
░░        ░░░ ░ ░   ░░   ░    ░       ░    ░   ░ ░   ░ ░ ░ ▒  ░ ░ ░ ▒   ░ ░  ░
            ░        ░        ░  ░    ░          ░  ░    ░ ░      ░ ░     ░

     {2}--={3}[ {0}{5}Author: Cr4sHCoD3                     {3}]{2}=--
{4}| {2}-- --={3}[ {0}{5}Version: 1                            {3}]{2}=-- -- {4}|
| {2}-- --={3}[ {0}{5}Website: https://github.com/cr4shcod3 {3}]{2}=-- -- {4}|
| {2}-- --={3}[ {0}{5}PureHackers ~ Blood Security Hackers  {3}]{2}=-- -- {4}|
{0}""".format(reset, red, green, blue, yellow, bold)).decode('utf-8')
    print (banner)



def set_url(target, wfunc):
    global url
    global hostname
    global ip
    if 'http://' in target:
        url = target
        hostname = target.replace('http://', '')
    elif 'https://' in target:
        url = target
        hostname = target.replace('https://', '')
    if '://' not in target:
        url = 'http://' + target
        hostname = target
    ip = socket.gethostbyname(hostname)
    if wfunc == 1:
        web_pentest()
    else:
        main()



def generator():
    print ("""\n\n
{3}[ {5}Generator {3}]

    {2}01{3}) {5}Deface Page
    {2}90{3}) {5}Back To Menu
    {2}99{3}) {5}Exit

{0}""".format(reset, red, green, blue, yellow, cyan))
    if sys.version_info[0] == 3:
        try:
            choice = int(input('{0}PureBlood{1}({3}Generator{1})> {2}'.format(green, blue, cyan, red)))
        except KeyboardInterrupt:
            print ('\n{2}[{1}+{2}] {3}- {4}Exiting...{0}'.format(reset, green, blue, yellow, cyan))
            sys.exit()
        except ValueError:
            print ('{2}[{1}+{2}] {3}- {4}Please enter a valid number!{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            main()
    elif sys.version_info[0] == 2:
        try:
            choice = int(raw_input('{0}PureBlood{1}({3}Generator{1})> {2}'.format(green, blue, cyan, red)))
        except KeyboardInterrupt:
            print ('\n{2}[{1}+{2}] {3}- {4}Exiting...{0}'.format(reset, green, blue, yellow, cyan))
            sys.exit()
        except ValueError:
            print ('{2}[{1}+{2}] {3}- {4}Please enter a valid number!{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            main()
    cgenerator = Generator()
    if choice == 1:
        print ('{0}='.format(red) * int(sizex))
        print (reset + bold)
        if sys.version_info[0] == 3:
            title = str(input('{0}PureBlood{1}>{0}Generator{1}>({3}Title{1})> {2}'.format(green, blue, cyan, red)))
            shortcut_icon = str(input('{0}PureBlood{1}>{0}Generator{1}>({3}Shortcut Icon{1})> {2}'.format(green, blue, cyan, red)))
            meta_description = str(input('{0}PureBlood{1}>{0}Generator{1}>({3}Meta Description{1})> {2}'.format(green, blue, cyan, red)))
            meta_image = str(input('{0}PureBlood{1}>{0}Generator{1}>({3}Meta Image{1})> {2}'.format(green, blue, cyan, red)))
            logo = str(input('{0}PureBlood{1}>{0}Generator{1}>({3}Logo{1})> {2}'.format(green, blue, cyan, red)))
            hacker_name = str(input('{0}PureBlood{1}>{0}Generator{1}>({3}Hacker Name{1})> {2}'.format(green, blue, cyan, red)))
            message1 = str(input('{0}PureBlood{1}>{0}Generator{1}>({3}Message 1{1})> {2}'.format(green, blue, cyan, red)))
            message2 = str(input('{0}PureBlood{1}>{0}Generator{1}>({3}Message 2{1})> {2}'.format(green, blue, cyan, red)))
            groups = str(input('{0}PureBlood{1}>{0}Generator{1}>({3}Group/s{1})> {2}'.format(green, blue, cyan, red)))
            deface_page_output_filename = str(input('{0}PureBlood{1}>{0}Generator{1}>({3}Output Filename{1})> {2}'.format(green, blue, cyan, red)))
        if sys.version_info[0] == 2:
            title = str(raw_input('{0}PureBlood{1}>{0}Generator{1}>({3}Title{1})> {2}'.format(green, blue, cyan, red)))
            shortcut_icon = str(raw_input('{0}PureBlood{1}>{0}Generator{1}>({3}Shortcut Icon{1})> {2}'.format(green, blue, cyan, red)))
            meta_description = str(raw_input('{0}PureBlood{1}>{0}Generator{1}>({3}Meta Description{1})> {2}'.format(green, blue, cyan, red)))
            meta_image = str(raw_input('{0}PureBlood{1}>{0}Generator{1}>({3}Meta Image{1})> {2}'.format(green, blue, cyan, red)))
            logo = str(raw_input('{0}PureBlood{1}>{0}Generator{1}>({3}Logo{1})> {2}'.format(green, blue, cyan, red)))
            hacker_name = str(raw_input('{0}PureBlood{1}>{0}Generator{1}>({3}Hacker Name{1})> {2}'.format(green, blue, cyan, red)))
            message1 = str(raw_input('{0}PureBlood{1}>{0}Generator{1}>({3}Message 1{1})> {2}'.format(green, blue, cyan, red)))
            message2 = str(raw_input('{0}PureBlood{1}>{0}Generator{1}>({3}Message 2{1})> {2}'.format(green, blue, cyan, red)))
            groups = str(raw_input('{0}PureBlood{1}>{0}Generator{1}>({3}Group/s{1})> {2}'.format(green, blue, cyan, red)))
            deface_page_output_filename = str(raw_input('{0}PureBlood{1}>{0}Generator{1}>({3}Output Filename{1})> {2}'.format(green, blue, cyan, red)))
        gdeface_page = cgenerator.deface_page(title, shortcut_icon, meta_description, meta_image, logo, hacker_name, message1, message2, groups)
        if '.html' in deface_page_output_filename:
            deface_page_output_filename = deface_page_output_filename
        else:
            deface_page_output_filename = deface_page_output_filename + '.html'
        deface_page_output_file = open('outputs/deface_page/' + deface_page_output_filename, 'w+')
        deface_page_output_file.write(gdeface_page)
        deface_page_output_file.close()
        print ('\n{2}[{1}+{2}] {3}- {4}Output saved in outputs/deface_page/' + deface_page_output_filename + '{0}'.format(reset, green, blue, yellow, cyan))
        print (reset + bold)
        print ('{0}='.format(red) * int(sizex))
        generator()
    elif choice == 90:
        print ('\n\n')
        main()
    elif choice == 99:
        print ('\n{2}[{1}+{2}] {3}- {4}Exiting...{0}'.format(reset, green, blue, yellow, cyan))
        sys.exit()
    else:
        print ('{2}[{1}+{2}] {3}- {4}Please enter a valid choice!{0}'.format(reset, green, blue, yellow, cyan))
        time.sleep(2)
        generator()



def web_pentest():
    global web_pentest_outputfile
    print ("""\n\n
{3}[ {5}Web Pentest {3}]

    {2}01{3}) {5}Banner Grab
    {2}02{3}) {5}Whois
    {2}03{3}) {5}Traceroute
    {2}04{3}) {5}DNS Record
    {2}05{3}) {5}Reverse DNS Lookup
    {2}06{3}) {5}Zone Transfer Lookup
    {2}07{3}) {5}Port Scan
    {2}08{3}) {5}Admin Panel Scan
    {2}09{3}) {5}Subdomain Scan
    {2}10{3}) {5}CMS Identify
    {2}11{3}) {5}Reverse IP Lookup
    {2}12{3}) {5}Subnet Lookup
    {2}13{3}) {5}Extract Page Links
    {2}90{3}) {5}Back To Menu
    {2}95{3}) {5}Set Target
    {2}99{3}) {5}Exit

{0}""".format(reset, red, green, blue, yellow, cyan))
    if sys.version_info[0] == 3:
        try:
            choice = int(input('{0}PureBlood{1}({3}WebPentest{1})> {2}'.format(green, blue, cyan, red)))
        except KeyboardInterrupt:
            try:
                print ('\n{2}[{1}+{2}] {3}- {4}Output saved in outputs/web_pentest/' + web_pentest_output + '{0}'.format(reset, green, blue, yellow, cyan))
            except:
                pass
            print ('\n{2}[{1}+{2}] {3}- {4}Exiting...{0}'.format(reset, green, blue, yellow, cyan))
            sys.exit()
        except ValueError:
            print ('{2}[{1}+{2}] {3}- {4}Please enter a valid number!{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            main()
    elif sys.version_info[0] == 2:
        try:
            choice = int(raw_input('{0}PureBlood{1}({3}WebPentest{1})> {2}'.format(green, blue, cyan, red)))
        except KeyboardInterrupt:
            try:
                print ('\n{2}[{1}+{2}] {3}- {4}Exiting...{0}'.format(reset, green, blue, yellow, cyan))
            except:
                pass
            sys.exit()
        except ValueError:
            print ('{2}[{1}+{2}] {3}- {4}Please enter a valid number!{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            main()
    cweb_pentest = WebPentest()
    if choice == 1:
        try:
            wp_banner_grab = cweb_pentest.banner_grab(url)
        except:
            print ('\n{2}[{1}!{2}] {3}- {4}Please set the target first. {1}95{2}) {4}Set Target{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            web_pentest()
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('[+] Banner Grab Result - ' + url)
        web_pentest_outputfile.write('\n============================================================')
        print (reset + bold)
        print (wp_banner_grab)
        web_pentest_outputfile.write('\n' + wp_banner_grab)
        print (reset)
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('\n')
        web_pentest_outputfile.write('============================================================\n')
        web_pentest()
    elif choice == 2:
        try:
            wp_whois = cweb_pentest.whois(url)
        except:
            print ('\n{2}[{1}!{2}] {3}- {4}Please set the target first. {1}95{2}) {4}Set Target{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            web_pentest()
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('[+] Whois Result - ' + url)
        web_pentest_outputfile.write('\n============================================================')
        print (reset + bold)
        print (wp_whois)
        web_pentest_outputfile.write('\n' + str(wp_whois))
        print (reset)
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('\n')
        web_pentest_outputfile.write('============================================================\n')
        web_pentest()
    elif choice == 3:
        try:
            wp_traceroute = cweb_pentest.traceroute(hostname)
        except:
            print ('\n{2}[{1}!{2}] {3}- {4}Please set the target first. {1}95{2}) {4}Set Target{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            web_pentest()
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('[+] Traceroute Result - ' + url)
        web_pentest_outputfile.write('\n============================================================')
        print (reset + bold)
        print (wp_traceroute)
        web_pentest_outputfile.write('\n' + wp_traceroute)
        print (reset)
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('\n')
        web_pentest_outputfile.write('============================================================\n')
        web_pentest()
    elif choice == 4:
        try:
            wp_dns_record = cweb_pentest.dns_record(hostname)
        except:
            print ('\n{2}[{1}!{2}] {3}- {4}Please set the target first. {1}95{2}) {4}Set Target{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            web_pentest()
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('[+] DNS Record Result - ' + url)
        web_pentest_outputfile.write('\n============================================================')
        print (reset + bold)
        web_pentest_outputfile.write('\n')
        for i in wp_dns_record:
            print (i)
            web_pentest_outputfile.write(str(i) + '\n')
        print (reset)
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('\n')
        web_pentest_outputfile.write('============================================================\n')
        web_pentest()
    elif choice == 5:
        try:
            wp_reverse_dns_lookup = cweb_pentest.reverse_dns_lookup(ip)
        except:
            print ('\n{2}[{1}!{2}] {3}- {4}Please set the target first. {1}95{2}) {4}Set Target{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            web_pentest()
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('[+] Reverse DNS Lookup Result - ' + url)
        web_pentest_outputfile.write('\n============================================================')
        print (reset + bold)
        print (wp_reverse_dns_lookup)
        web_pentest_outputfile.write('\n' + wp_reverse_dns_lookup)
        print (reset)
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('\n')
        web_pentest_outputfile.write('============================================================\n')
        web_pentest()
    elif choice == 6:
        try:
            wp_zone_transfer_lookup = cweb_pentest.zone_transfer_lookup(hostname)
        except:
            print ('\n{2}[{1}!{2}] {3}- {4}Please set the target first. {1}95{2}) {4}Set Target{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            web_pentest()
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('[+] Zone Transfer Lookup Result - ' + url)
        web_pentest_outputfile.write('\n============================================================')
        print (reset + bold)
        print (wp_zone_transfer_lookup)
        web_pentest_outputfile.write('\n' + wp_zone_transfer_lookup)
        print (reset)
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('\n')
        web_pentest_outputfile.write('============================================================\n')
        web_pentest()
    elif choice == 7:
        if sys.version_info[0] == 3:
            port_end = int(input('{0}PureBlood{1}>{0}WebPentest{1}>{0}PortScan{1}>({3}Port End{1})> {2}'.format(green, blue, cyan, red)))
        if sys.version_info[0] == 2:
            port_end = int(raw_input('{0}PureBlood{1}>{0}WebPentest{1}>{0}PortScan{1}>({3}Port End{1})> {2}'.format(green, blue, cyan, red)))
        try:
            wp_port_scan = cweb_pentest.port_scan(hostname, port_end)
        except:
            print ('\n{2}[{1}!{2}] {3}- {4}Please set the target first. {1}95{2}) {4}Set Target{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            web_pentest()
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('[+] Port Scan Result - ' + url)
        web_pentest_outputfile.write('\n============================================================')
        print (reset + bold)
        web_pentest_outputfile.write('\n')
        for i in wp_port_scan:
            print (i)
            web_pentest_outputfile.write(str(i) + '\n')
        print (reset)
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('\n')
        web_pentest_outputfile.write('============================================================\n')
        web_pentest()
    elif choice == 8:
        try:
            wp_admin_panel_scan = cweb_pentest.admin_panel_scan(url)
        except:
            print ('\n{2}[{1}!{2}] {3}- {4}Please set the target first. {1}95{2}) {4}Set Target{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            web_pentest()
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('[+] Admin Panel Scan Result - ' + url)
        web_pentest_outputfile.write('\n============================================================')
        print (reset + bold)
        web_pentest_outputfile.write('\n')
        for i in wp_admin_panel_scan:
            print (i)
            web_pentest_outputfile.write(str(i) + '\n')
        print (reset)
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('\n')
        web_pentest_outputfile.write('============================================================\n')
        web_pentest()
    elif choice == 9:
        if sys.version_info[0] == 3:
            subdomain_list = str(input('{0}PureBlood{1}>{0}WebPentest{1}>{0}SubdomainScan{1}>({3}Subdomain List{1})> {2}'.format(green, blue, cyan, red)))
        if sys.version_info[0] == 2:
            subdomain_list = str(raw_input('{0}PureBlood{1}>{0}WebPentest{1}>{0}SubdomainScan{1}>({3}Subdomain List{1})> {2}'.format(green, blue, cyan, red)))
        try:
            wp_subdomain_scan = cweb_pentest.subdomain_scan(hostname, subdomain_list)
        except:
            print ('\n{2}[{1}!{2}] {3}- {4}Please set the target first. {1}95{2}) {4}Set Target{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            web_pentest()
        so_200, so_301, so_302, so_403 = wp_subdomain_scan
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('[+] Subdomain Scan Result - ' + url)
        web_pentest_outputfile.write('\n============================================================')
        print (reset + bold)
        web_pentest_outputfile.write('\n')
        for i in so_200:
            print ('[+] 200 - ' + i)
            web_pentest_outputfile.write('[+] 200 - ' + i + '\n')
        for i in so_301:
            print ('[!] 301 - ' + i)
            web_pentest_outputfile.write('[+] 301 - ' + i + '\n')
        for i in so_302:
            print ('[!] 302 - ' + i)
            web_pentest_outputfile.write('[+] 302 - ' + i + '\n')
        for i in so_403:
            print ('[!] 403 - ' + i)
            web_pentest_outputfile.write('[+] 403 - ' + i + '\n')
        print (reset)
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('\n')
        web_pentest_outputfile.write('============================================================\n')
        web_pentest()
    elif choice == 10:
        try:
            wp_cms_detect = cweb_pentest.cms_detect(hostname)
        except:
            print ('\n{2}[{1}!{2}] {3}- {4}Please set the target first. {1}95{2}) {4}Set Target{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            web_pentest()
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('[+] CMS Detect - ' + url)
        web_pentest_outputfile.write('\n============================================================')
        print (reset + bold)
        print (wp_cms_detect)
        web_pentest_outputfile.write('\n' + wp_cms_detect)
        print (reset)
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('\n')
        web_pentest_outputfile.write('============================================================\n')
        web_pentest()
    elif choice == 11:
        try:
            wp_reverse_ip_lookup = cweb_pentest.reverse_ip_lookup(hostname)
        except:
            print ('\n{2}[{1}!{2}] {3}- {4}Please set the target first. {1}95{2}) {4}Set Target{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            web_pentest()
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('[+] Reverse IP Lookup Result - ' + url)
        web_pentest_outputfile.write('\n============================================================')
        print (reset + bold)
        print (wp_reverse_ip_lookup)
        web_pentest_outputfile.write('\n' + wp_reverse_ip_lookup)
        print (reset)
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('\n')
        web_pentest_outputfile.write('============================================================\n')
        web_pentest()
    elif choice == 12:
        if sys.version_info[0] == 3:
            subnet_input = str(input('{0}PureBlood{1}>{0}WebPentest{1}>{0}SubnetLookup{1}>({3}CIDR or IP with NetMask{1})> {2}'.format(green, blue, cyan, red)))
        if sys.version_info[0] == 2:
            subnet_input = str(raw_input('{0}PureBlood{1}>{0}WebPentest{1}>{0}SubnetLookup{1}>({3}CIDR or IP with NetMask{1})> {2}'.format(green, blue, cyan, red)))
        try:
            wp_subnet_lookup = cweb_pentest.subnet_lookup(subnet_input)
        except:
            print ('\n{2}[{1}!{2}] {3}- {4}Please set the target first. {1}95{2}) {4}Set Target{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            web_pentest()
        print ('{0}='.format(red) * int(sizex))
        print (reset + bold)
        print (wp_subnet_lookup)
        print (reset)
        print ('{0}='.format(red) * int(sizex))
        web_pentest()
    elif choice == 13:
        try:
            wp_links_extract = cweb_pentest.links_extract(url)
        except:
            print ('\n{2}[{1}!{2}] {3}- {4}Please set the target first. {1}95{2}) {4}Set Target{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            web_pentest()
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('[+] Links Extract Result - ' + url)
        web_pentest_outputfile.write('\n============================================================')
        print (reset + bold)
        print (wp_links_extract)
        web_pentest_outputfile.write('\n' + wp_links_extract)
        print (reset)
        print ('{0}='.format(red) * int(sizex))
        web_pentest_outputfile.write('\n')
        web_pentest_outputfile.write('============================================================\n')
        web_pentest()
    elif choice == 90:
        print ('\n\n')
        main()
    elif choice == 95:
        print ('{2}[{1}#{2}] {3}- {4}Please don\'t put "/" in the end of the Target.{0}'.format(reset, green, blue, yellow, cyan))
        if sys.version_info[0] == 3:
            target = str(input('{0}PureBlood{1}>{0}WebPentest{1}>({3}Target{1})> {2}'.format(green, blue, cyan, red)))
        if sys.version_info[0] == 2:
            target = str(raw_input('{0}PureBlood{1}>{0}WebPentest{1}>({3}Target{1})> {2}'.format(green, blue, cyan, red)))
        if '://' in target:
            ourl = target.replace('https://', '').replace('http://', '')
        else:
            ourl = target
        web_pentest_output = ourl + '-' + month + mday + '.txt'
        web_pentest_outputfile = open('outputs/web_pentest/' + web_pentest_output, 'a+')
        web_pentest_outputfile.write('\n\n\n[#] - ' + month + ' ' + mday + ' ' + current_time + '\n')
        set_url(target, 1)
    elif choice == 99:
        try:
            print ('\n{2}[{1}+{2}] {3}- {4}Output saved in outputs/web_pentest/' + web_pentest_output + '{0}'.format(reset, green, blue, yellow, cyan))
        except:
            pass
        print ('\n{2}[{1}+{2}] {3}- {4}Exiting...{0}'.format(reset, green, blue, yellow, cyan))
        sys.exit()
    else:
        print ('{2}[{1}+{2}] {3}- {4}Please enter a valid choice!{0}'.format(reset, green, blue, yellow, cyan))
        time.sleep(2)
        web_pentest()



def main():
    print ("""
{3}[ {5}PureBlood Menu {3}]

    {2}01{3}) {5}Web Pentest
    {2}02{3}) {5}Generator
    {2}99{3}) {5}Exit

{0}""".format(reset, red, green, blue, yellow, cyan))
    if sys.version_info[0] == 3:
        try:
            choice = int(input('{0}PureBlood{1}> {2}'.format(green, blue, cyan)))
        except KeyboardInterrupt:
            print ('\n{2}[{1}+{2}] {3}- {4}Exiting...{0}'.format(reset, green, blue, yellow, cyan))
            sys.exit()
        except ValueError:
            print ('{2}[{1}+{2}] {3}- {4}Please enter a valid number!{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            print ('\n\n')
            main()
    elif sys.version_info[0] == 2:
        try:
            choice = int(raw_input('{0}PureBlood{1}> {2}'.format(green, blue, cyan)))
        except KeyboardInterrupt:
            print ('\n{2}[{1}+{2}] {3}- {4}Exiting...{0}'.format(reset, green, blue, yellow, cyan))
            sys.exit()
        except ValueError:
            print ('{2}[{1}+{2}] {3}- {4}Please enter a valid number!{0}'.format(reset, green, blue, yellow, cyan))
            time.sleep(2)
            print ('\n\n')
            main()
    if choice == 1:
        web_pentest()
    elif choice == 2:
        generator()
    elif choice == 99:
        print ('\n{2}[{1}+{2}] {3}- {4}Exiting...{0}'.format(reset, green, blue, yellow, cyan))
        sys.exit()
    else:
        print ('{2}[{1}+{2}] {3}- {4}Please enter a valid choice!{0}'.format(reset, green, blue, yellow, cyan))
        time.sleep(2)
        print ('\n\n')
        main()



if __name__ == '__main__':
    if not os.path.exists('outputs'):
        os.mkdir('outputs')
    else:
        pass
    if not os.path.exists('outputs/generator'):
        os.mkdir('outputs/generator')
    else:
        pass
    if not os.path.exists('outputs/web_pentest'):
        os.mkdir('outputs/web_pentest')
    else:
        pass
    clear()
    banner()
    google_hacking = 'https://www.google.com/search?q='
    main()
