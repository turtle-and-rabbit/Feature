#!/usr/bin/env python
# coding: utf-8

# In[11]:


from urllib.parse import urlparse
from urllib.request import urlopen
from dateutil.parser import parse
from bs4 import BeautifulSoup
from datetime import datetime
from tld import get_tld
import requests
import ssl, socket
import whois, sys
import re
from datetime import timedelta
    
    
## 02 feature
def URL_Length(url) :
    if len(url) < 54 :
        return 1
    elif len(url) >= 54 and len(url) <= 75 :
        return 0
    else :
        return -1

    
## 03 feature
def Shortening_Service(resp, url) :
    redirect = 1
    origin_url = url
    redirectCount = 0
    
    # redirection detect
    for respl in resp.history :
        if respl.status_code == 301 or respl.status_code == 302 :
            redirect = -1
        redirectCount += 1
         
    origin_url = resp.url
    return origin_url, redirect, redirectCount
    
    
## 04 feature
def having_At_Symbol(url) :
    listurl = list(url)
    return -1 if '@' in listurl else 1
    
    
## 05 feature
def double_slash_redirecting(url) :
    return -1 if '//' in url else 1

    
## 06 feature
def Prefix_Suffix(url):
    listurl = list(url)
    return -1 if '-' in listurl else 1
    
    
## 07 feature
def having_Sub_Domain(url, tld) :
    url = remove_www(url)
    #print(domain.subdomain)
    if tld.subdomain == "" :
        return 1
    dot = tld.subdomain.count('.')
    if dot == 0 :
        return 0
    else :
        return -1

# URL에서 "www."을 제거해서 돌려줍니다.
def remove_www(url) :
    if "www." in url[:12] :
        url = url.replace("www.", "")
    return url


## 08 feature
def SSLfinal_State(url) :
    try :
        s = https_connect(url)
    except TimeoutError :
        return -1
    cert = s.getpeercert()
    issuer = dict(x[0] for x in cert['issuer'])
    issued_by = issuer['organizationName']
    
    trusted_issuer_list = get_trusted_issuer()
    for trusted_issuer in trusted_issuer_list :
        if trusted_issuer == issued_by :
            break
    else :
        return 0
    
    notAfter = cert['notAfter']
    notBefore = cert['notBefore']
    init_date = parse(notBefore)
    expiration_date = parse(notAfter)
    total_days = (expiration_date.date() - init_date.date()).days
    #print(total_days)
    if total_days >= 365 :
        return 1
    else :
        return 0

# https socket connection
def https_connect(url) :
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.socket(), server_hostname=url)
    s.connect((url, 443))
    return s

# Read trusted issuer file
def get_trusted_issuer():
    f = open("trusted_issuer_list.txt", "r")
    
    trusted_issuer = []
    for line in f :
        issuers = line.strip('\n')
        trusted_issuer.append(issuers)
    return trusted_issuer


## 09 feature
def Domain_registeration_length(url, domain_info) :
    try :
        total_date = get_remain_date(domain_info)
        if total_date <= 365 :
            return -1
        else :
            return 1
    except (whois.parser.PywhoisError) :
        return -1

# domain의 남은 기간 계산
def get_remain_date(domain_info) :
    if type(domain_info.expiration_date) is list :
        expiration_date = domain_info.expiration_date[0]
    else :
        expiration_date = domain_info.expiration_date
        
    if type(domain_info.updated_date) is list :
        updated_date = domain_info.updated_date[0]
    else :
        updated_date = domain_info.updated_date
        
    total_date = (expiration_date - updated_date).days
    
    return total_date


## 10 feature
def Favicon(url, soup):
    tag_link = soup.findAll("link", rel="shortcut icon")
    if not tag_link :
        return 1
    
    for link in tag_link:
        #print(link.get('href'))
        parse = urlparse(link.get('href'))
        #print(parse)
        if parse.netloc == "":
            return 1
        else:
            return -1

        
## 11 feature
def Port(domain):
    try :
        ip = socket.gethostbyname(domain)
    except :
        return -1
    
    socket.setdefaulttimeout(2)
    
    ports = [80, 21, 22, 23, 445, 1433, 1521, 3306, 3389]
    for port in ports :
        s = socket.socket()
        if port == 80 :
            try :
                s.connect((ip, port))
                s.close()
            except :
                return -1
        else :
            try :
                s.connect((ip, port))
                s.close()
                return -1
            except :
                pass
            
    return 1


## 12 feature
def HTTPS_token(url):
    return -1 if "http://https" in url else 1


## 13 feature
def Request_URL(soup, tld):
    
    count = 0 #전체 개체 갯수 count용
    pattern = re.compile("^(http|https|www)((?!"+tld.fld+").)*$") #외부 개체 url 검사할 정규식
    externalLinks=[] #외부 개체 경로 저장
    percent = 0
    
    for i in soup.findAll('a',href=True): #외부링크검사
        count += 1
        if re.search(pattern, i.attrs['href']) is not None:
            externalLinks.append(i.attrs['href'])
    for i in soup.findAll('img', src=True):
        count += 1
        if re.search(pattern, i.attrs['src']) is not None:
            externalLinks.append(i.attrs['src'])
    for i in soup.findAll('audio', src=True):
        count += 1
        if re.search(pattern, i.attrs['src']) is not None:
            externalLinks.append(i.attrs['src'])
    for i in soup.findAll('embed', src=True):
        count += 1
        if re.search(pattern, i.attrs['src']) is not None:
            externalLinks.append(i.attrs['src'])
    for i in soup.findAll('i_frame', src=True):
        count += 1
        if re.search(pattern, i.attrs['src']) is not None:
            externalLinks.append(i.attrs['src'])
    countex = len(externalLinks) #외부 개체 갯수
    #print(countex) #외부 개체 갯수 출력
    #print(count) #전체 개체 갯수 출력
    
    if count == 0:
        return 1
    percent = countex/count * 100
    if percent < 22:
        return 1
    elif 22 <= percent <= 61:
        return 0
    else:
        return -1

    
## 14 feature
def URL_of_Anchor(soup):
    tagAList = soup.findAll('a', href=True)

    cstr1 = 'href="#'
    cstr2 = 'href="JavaScript'

    suscount = 0

    for i in tagAList:
        if cstr1 in str(i):
            suscount += 1
        elif cstr2 in str(i):
            suscount += 1
          
    allcount = len(tagAList)

    if allcount == 0:
        return 1
    percent = (suscount/allcount)*100

    if percent < 22:
        return 1
    elif 22 <= percent <= 61:
        return 0
    else:
        return -1

    
## 15 feature
def Links_in_tags(soup):
    tagMSLList = soup.findAll(["meta", "script", "link"])
    tagAll = soup.findAll()

    lenMSL = len(tagMSLList)
    lenAll = len(tagAll)
    percentage = (lenMSL/lenAll)*100

    if percentage < 17:
        return 1
    elif 17 <= percentage <= 81:
        return 0
    else:
        return -1

    
## 16 feature
def SFH(soup, tld): 
    pattern = re.compile("^(http|https)((?!"+tld.fld+").)*$")
    tagForm = soup.findAll('form', action=True)
    for i in tagForm:
        if "" in i['action'] or "about:blank" in i['action']:
            return -1  
        elif re.search(pattern, i.attrs['action']) is not None:
            return 0
        else:
            return 1
    else :
        return 1
        
        
## 17 feature
def Submitting_to_email(soup):
    tagForm = soup.findAll('form', action=True)
#     print(tagForm)
    for i in tagForm:
        if "mailto:" in i['action'] :
            return -1  
        else :
            return 1
    else :
        return 1

    
## 18 feature
def Abnormal_URL(url, domain_info, tld):
    hostname = tld.fld
    checkdomain = domain_info.domain_name
    return 1 if hostname in checkdomain else -1


## 19 feature
def Redirect(redirectCount):
    if redirectCount <= 1:
        return 1
    elif 2<= redirectCount <= 4:
        return 0
    else:
        return -1

    
## 20 feature
def on_mouseover(soup):
    tagA = soup.findAll('a', onmouseover=True)
    tagScript = soup.findAll('script')
    
    def ChecktagA(tagA):
        for i in tagA:
            if 'window.status' in i['onmouseover']:
                 return -1
        return 1
    
    def ChecktagS(tagScript):
        for i in tagScript:
            if 'window.status' in i.get_text():
                return -1
        return 1
    
    if ChecktagA == -1 or ChecktagS == -1:
        return -1
    else:
        return 1

    
## 21 feature
def Disabling_Right_Click(soup):
    source = str(soup)
    
    if source.find("event.button==2") != -1: return -1
    if source.find("event.button ==2") != -1: return -1
    if source.find("event.button== 2") != -1: return -1
    if source.find("event.button == 2") != -1: return -1
    
    return 1


## 22 feature
def Using_Pop_up_Window(soup):
    
    source = str(soup)
    if source.find("prompt(") != -1: return -1
    
    while True:
        index = source.find("window.open('http")
        if index == -1: break

        source = source[index:]
        index = source.find("http")
        source = source[index:]
        
        index = source.find(",")
        while source[index-1] == " ": index -= 1
        index -= 1
        
        Pop_url = source[:index]
        Pop_res = urlopen(Pop_url)
        Pop_html = Pop_res.read()
        Pop_soup = BeautifulSoup(Pop_html, "html.parser")
            
        Pop_source = str(Pop_soup)
        
        search = re.compile("[\s\S]*input\stype\s*=\s*\"text\"")
        check = search.match(Pop_source)
    
        if check != None: return -1
        source = source[1:]

    return 1


## 23 feature
def IFrame_Redirection(soup):
    for i_frame in soup.find_all('iframe', width=True, height=True, frameBorder=True):
        if i_frame['width'] == "0" and i_frame['height'] == "0" and i_frame['frameBorder'] == "0":
            return -1
    return 1
    
    
## 24 feature
def Age_of_Domain(domain_info):
    #print(domain_info)
    now = datetime.today()
    now = now.date()
    url_info = domain_info.creation_date
    
    if url_info == "before Aug-1996" :
        url_info = datetime(1996, 8, 1)
    
    if type(url_info) == list: 
        url_info = domain_info.creation_date[0]
        
    url_info = url_info.date()

    days = timedelta(days=180)
    if now - url_info >= days: return 1
    return -1


# ## 25 feature
# def DNS_Record(domain_info):
#     url_domain = 0
#     url_domain = domain_info
#     if url_domain != 0: return 1 # 도메인이 존재하면 정상
#     return 0
    
    
## 26 feature
def Web_Traffic(url) :
    req = urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url)
    
    try :
        ranking = int(BeautifulSoup(req.read(), "xml").find("REACH")["RANK"])
    except TypeError :
        return -1
    
    #print(ranking)
    if ranking <= 100000 :
        return 1
    elif ranking > 100000 :
        return 0
    else :
        return -1

    
## 27 feature
#def PageRank(url):
    
    
## 28 feature
def Google_Index(resp):
    #headers = {'User-Agent' : 'Mozilla/5.0'}
    #res = requests.get(url, headers=headers) # get 결과
    if resp.status_code == 200: return 1 # 
    return -1


## 29 feature
#def Number_of_Links_Pointing_to_Page(url):
    
    
## 30 feature
def Statistical_Reports_Based_Feature(url, ip_address):
    url_match = re.search(
        'esy\.es|hol\.es|000webhostapp\.com|16mb\.com|bit\.ly|for-our\.info|beget\.tech|blogspot\.com|weebly\.com|raymannag\.ch', url)

    ip_match = re.search(
        '''
        146\.112\.61\.108|31\.170\.160\.61|67\.199\.248\.11|67\.199\.248\.10|69\.50\.209\.78|192\.254\.172\.78|216\.58\.193\.65|23\.234\.229\.68|173\.212\.223\.160|60\.249\.179\.122|
        64\.70\.19\.203|142\.111\.127\.186|74\.117\.221\.144|54\.83\.43\.69|52\.80\.8\.80|216\.218\.185\.162|175\.126\.123\.219|47\.91\.170\.222|108\.61\.203\.22|23\.20\.239\.12|
        173\.230\.141\.80|153\.92\.0\.100|216\.58\.194\.129|172\.217\.9\.1|209\.126\.123\.12|184\.168\.131\.241|141\.8\.224\.221|209\.202\.252\.66|91\.195\.240\.126|91\.227\.52\.108|
        199\.59\.242\.151|103\.243\.24\.98|52\.58\.78\.16|216\.58\.194\.33|18\.211\.9\.206|128\.14\.145\.226|128\.14\.145\.227|69\.172\.201\.153|192\.169\.81\.126|211\.231\.99\.250|
        25\.186\.238\.101|193\.109\.247\.10|94\.199\.53\.203|67\.227\.226\.240|193\.109\.247\.160|47\.91\.202\.66|204\.11\.56\.48|37\.157\.192\.102|192\.64\.147\.171|198\.11\.172\.242|
        23\.253\.126\.58|138\.201\.122\.249|104\.239\.157\.210|193\.109\.247\.247|193\.109\.247\.223|208\.91\.197\.46|158\.69\.25\.93|5\.57\.226\.202|31\.170\.160\.57|172\.247\.235\.12|
        ''', ip_address)
    
    if url_match:
        return -1
    elif ip_match:
        return -1
    else:
        return 1
    

def main(url):
    headers = {'User-Agent' : 'Mozilla/5.0'}
    resp = requests.get(url, headers=headers)
    
    # URL이 연결되는지, 유효한지 검사 (수정해야될 것 같음)
    try :
        url, redirect, redirectCount = Shortening_Service(resp, url)
        print(url)
    except ConnectionError :
        # 존재하지 않는 URL or 연결할 수 없는 URL인 경우 처리
        pass
    
    parse = urlparse(url)
    #print(parse)
    scheme = parse.scheme
    domain = parse.netloc
    
    fail_lookup = 0
    try :
        ip_address = socket.gethostbyname(domain)
    except :
        fail_lookup = 1
    
    path = parse.path
    req = urlopen(url)
    soup = BeautifulSoup(req, 'html.parser')
    tld = get_tld(url, as_object=True)
    
    checkNotWhois = 0
    try :
        domain_info = whois.whois(url)
        if type(domain_info) == whois.parser.WhoisEntry:
            checkNotWhois = 1
    except whois.parser.PywhoisError :
        checkNotWhois = 1
    
    features = []
    
#     features.append(having_IP_Address(domain))
    features.append(URL_Length(url))
    features.append(redirect)
    features.append(having_At_Symbol(url))
    features.append(double_slash_redirecting(path))
    
    features.append(Prefix_Suffix(url))
    
    if features[0] == -1 :
        features.append(-1)
    else :
        features.append(having_Sub_Domain(url, tld))
    
    if scheme == "http" :
        features.append(-1)
    else :
        features.append(SSLfinal_State(domain))
    
    if features[0] == -1 :
        features.append(-1)
    elif checkNotWhois :
        features.append(1)
    else :
        features.append(Domain_registeration_length(url, domain_info))
    
    features.append(Favicon(url, soup))
    if scheme != "https" or fail_lookup :
        features.append(-1)
    else :
        features.append(Port(ip_address))

    features.append(HTTPS_token(url))
    features.append(Request_URL(soup, tld))
    features.append(URL_of_Anchor(soup))
    features.append(Links_in_tags(soup))
    features.append(SFH(soup, tld))
    features.append(Submitting_to_email(soup))
    
    if checkNotWhois :
        features.append(1)
    else :
        features.append(Abnormal_URL(url, domain_info, tld))
    
    features.append(Redirect(redirectCount))
    features.append(on_mouseover(soup))

    features.append(Disabling_Right_Click(soup))
    features.append(Using_Pop_up_Window(soup))
    features.append(IFrame_Redirection(soup))
    
    if checkNotWhois :
        features.append(1)
        features.append(-1)
    else :
        features.append(Age_of_Domain(domain_info))
        features.append(1)
    
    features.append(Web_Traffic(url))
    #features.append(PageRank(url))
    features.append(Google_Index(resp))
    #features.append(Number_of_Links_Pointing_to_Page(url))
    if fail_lookup :
        features.append(-1)
    else :
        features.append(Statistical_Reports_Based_Feature(url, ip_address))
    
    print(features)
    print(len(features))


# In[20]:


sample_url_1 = "https://blog.naver.com/is_king"

sample_url_2 = "https://www.hackerschool.org/Sub_Html/HS_Community/index.html?Type=Board&BID=Free_Board"

sample_url_3 = "https://bit.ly/2JOMr6V"

sample_url_4 = "https://bit.ly/2qxAaYw"

sample_url_5 = "http://192.168.174.137/bWAPP/login.php"

sample_url_6 = "http://ftp.kaist.ac.kr"

phishing_url_1 = "https://voknhjuiuy.000webhostapp.com/"

phishing_url_2 = "http://heysunglasses.com/wp-content/plugins/ubh/outi/our.html"

phishing_url_3 = "http://www.litopia21.com/morningform/newupdate.htm"

phishing_url_4 = "https://profile-user.com/"

phishing_url_5 = "http://wildcard.montconghana.com/usaa.com-inet-trueMemberent-IsCADdetour-start"

phishing_url_6 = "http://codeinmood.info/fonts/zzzz/"

phishing_url_7 = "http://groups.csail.mit.edu/mac/ftpdir/scm/"

main(phishing_url_2)


# req = urlopen(sample_url_2)
# soup = BeautifulSoup(req, 'html.parser')

# Using_Pop_up_Window("www.hackerschool.org", soup)

# main(sample_url_2)
#main(sample_url_3)
#main(sample_url_4)
#main(sample_url_5)


# In[104]:


import numpy as np
from io import StringIO
import csv


f = open("new_dataset.csv", "a", encoding="UTF-8", newline="")
csv_wr = csv.writer(f)
for i in range(len(url)) :
    csv_wr.writerow( [url[i]])

