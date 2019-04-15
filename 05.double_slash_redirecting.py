#!/usr/bin/env python
# coding: utf-8

# In[10]:


import urllib.parse

sample_url_1 = "http://192.168.111.33/bWAPP/login.php"
sample_url_2 = "https://blog.naver.com//http://www.phishing.com"
parse = urllib.parse.urlparse(sample_url_2)


def double_slash_redirecting() :
    try :
        parse.path.index('//')
        return -1
    except ValueError :
        return 1

attr_5 = double_slash_redirecting()
print(attr_5)

