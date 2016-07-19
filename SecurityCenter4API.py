
# This sample python script demonstrates how to log in the SecurityCenter 4 API
# and retrieve a list of the First 100 Critical Vulnerabilities
# You will be required to set the URL, Username, and Password for your
# SecurityCenter installation in the appropiate area below.

# The SecurityCenter 4 API documentation can be referenced to modify this
# script and retrieve additional information.

# Simply create a new def() with your requirements.

"""
name:        SecurityCenter5API.py
description: A script for accessing Tenable's SecurityCenter 4.x.x via API

license :    GPL-3.0
             SEE LICENSE IN LICENSE.txt

author :     Josef Weiss
email :      josef -at- josefweiss.com
url :        http://josefweiss.com

"""


import urllib2
import urllib
import json


def connect(module, action, input={}):
    data = {'module': module,
            'action': action,
            'input': json.dumps(input),
            'token': token,
            'request_id': 1}

    headers = {'Cookie': 'TNS_SESSIONID=' + cookie}

    url = server + '/request.php'

    try:
        request = urllib2.Request(url, urllib.urlencode(data), headers)
        response = urllib2.urlopen(request)
        content = json.loads(response.read())
        return content['response']

    except Exception, e:
        print "Error: " + str(e)
        return None

# Set the specifics here by entering the following information in this format:
# server = 'https://mysc.mydomain.com'
# username = 'mySecurityCenterUserName'
# password = 'mySecurityCenterPassword'
# ===========================================
server = 'https://SC.URL.HERE'
username = 'USERNAME'
password = 'PASSWORD'
# ===========================================
# DO NOT MODIFY THE TOKEN OR COOKIE
token = ''
cookie = ''

input = {'username': username, 'password': password}
resp = connect('auth', 'login', input)
token = resp['token']
cookie = resp['sessionID']


# Query the SC server to get the first 100 critical vulnerabilities.
# The value of 4 is Critical, 3 is High, 2 is Medium, 1 is Low

def first100CriticalVulnerabilities():
    filters = [{'filterName': 'severity',
                'operator': '=',
                'value': '4'}]

    input = {'tool': 'vulndetails',
             'sourceType': 'cumulative',
             'filters': filters,
             'startOffset': 0,
             'endOffset': 100}

    vulns = connect('vuln', 'query', input)
    print
    print 'First 100 Critical Vulnerabilities'
    print '=================================='
    print
    for vuln in vulns['results']:
        print 'IP: ' + vuln['ip']
        print 'Name: ' + vuln['pluginName']
        print 'Severity: ' + vuln['severity']
        print

print first100CriticalVulnerabilities()


