import sys
import requests
import threading
import re
http_sources = [
    'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
    'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt',
    'https://openproxylist.xyz/http.txt',
    'https://sunny9577.github.io/proxy-scraper/generated/http_proxies.txt',
    'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
    'https://openproxy.space/list/http',
    'https://proxyspace.pro/http.txt',
    'https://proxyspace.pro/https.txt',
    'https://raw.githubusercontent.com/aslisk/proxyhttps/main/https.txt',
    'https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt',
    'https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt',
    'https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http_old.txt',
    'https://www.proxy-list.download/api/v1/get?type=https',
    'https://raw.githubusercontent.com/casals-ar/proxy-list/main/http',
    'https://raw.githubusercontent.com/casals-ar/proxy-list/main/https',
    'https://raw.githubusercontent.com/im-razvan/proxy_list/main/http.txt',
    'https://raw.githubusercontent.com/saisuiu/Lionkings-Http-Proxys-Proxies/main/free.txt',
    'https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/http/global/http_checked.txt',
    'https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt',
    'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt',
    'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt',
    'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt',
    'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt',
    'https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt',
    'https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/https_proxies.txt',
    'https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt',
    'https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/https/https.txt',
    'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt'
]
socks5_source = [
    'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all&ssl=all&anonymity=all',
    'https://www.proxy-list.download/api/v1/get?type=socks5',
    'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt',
    'https://openproxylist.xyz/socks5.txt',
    'https://sunny9577.github.io/proxy-scraper/generated/socks5_proxies.txt',
    'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
    'https://openproxy.space/list/socks5',
    'https://proxyspace.pro/socks5.txt',
    'https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt',
    'https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt',
    'https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks5/socks5.txt',
    'https://raw.githubusercontent.com/casals-ar/proxy-list/main/socks5',
    'https://raw.githubusercontent.com/im-razvan/proxy_list/main/socks5.txt',
    'https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/socks5/global/socks5_checked.txt',
    'https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt',
    'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt',
    'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt',
    'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt',
    'https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/socks5_proxies.txt',
    'https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt'
]
proxies = []

lock = threading.RLock()

def delete_duplicates(duplicates):
    duplicates = set(duplicates)
    duplicates = list(duplicates)
    return duplicates

def parse_proxies(content):
    proxies_content = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}', content)
    return delete_duplicates(proxies_content)

def scrape(source):
    response = requests.get(source)
    if response.status_code != 200:
        print(source)
    scraped_proxies = parse_proxies(response.text)
    proxies.extend(scraped_proxies)

threads = []
for source in list(http_sources if sys.argv[1] == 'http' else socks5_source):
    thread = threading.Thread(target=scrape, args=(source, ), daemon=True)
    thread.start()
    threads.append(thread)
for thread in threads:
    thread.join()
proxies = delete_duplicates(proxies)
print('Thành Công! , Có ' + len(proxies).__str__() + ' Proxy')
with open('proxy.txt', 'wb') as file:
    line = bytes('\n'.join(proxies), encoding='utf8')
    file.write(line)
    file.close()