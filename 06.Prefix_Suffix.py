def checkUrl(url):
    a = list(url)
    if '-' in a:
        return -1
    else:
        return 1


url = "helods-ensl"
print(checkUrl(url))
#return checkUrl(url)
