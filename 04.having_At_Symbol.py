#!/usr/bin/env python
# coding: utf-8

# In[9]:


import urllib.parse

sample_url_1 = "http://192.168.111.33@/bWAPP/login.php"
sample_url_2 = "https://blog.naver.com/is_king/221383568264"
parse = urllib.parse.urlparse(sample_url_1)

def having_At_Symbol() :
    if '@' in parse.netloc :
        return 1
    else :
        return -1

attr_4 = having_At_Symbol()
print(attr_4)

