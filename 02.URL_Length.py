#!/usr/bin/env python
# coding: utf-8

# In[23]:


sample_url_1 = "http://192.168.111.33dddddddddddddddd/bWAPP/login.php"
sample_url_2 = "https://blog.naver.com/is_king/221383568264"

def URL_Length() :
    if len(sample_url_1) < 54 :
        return 1
    elif len(sample_url_1) >= 54 and len(sample_url_1) <= 75 :
        return 0
    else :
        return -1

attr_2 = URL_Length()
print(attr_2)

