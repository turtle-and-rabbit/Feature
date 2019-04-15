#!/usr/bin/env python
# coding: utf-8

# In[19]:


import whois
import sys
from datetime import datetime, timedelta

sample_url_1 = "hackerschool.org"
# sample_url_1 expiration_date > 365 days
sample_url_2 = "asd12415sacxdasda.com"
# sample_url_2 invalid URL

def Domain_registeration_length() :
    if remain_date <= 365 :
        return -1
    else :
        return 1;

try :
    domain = whois.whois(sample_url_2)
    cur_date = datetime.now()
    expiration_date = domain.expiration_date
    remain_date = (expiration_date - cur_date).days
    print(remain_date)
    attr9 = Domain_registeration_length()
except (whois.parser.PywhoisError) :
    print("PywhoisError!!")
    attr9 = -1

print(attr9)

