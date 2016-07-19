
"""
name:        SecurityCenter5API.py
description: A script for accessing Tenable's SecurityCenter 5.x.x via API

license :    GPL-3.0
             SEE LICENSE IN LICENSE.txt

author :     Josef Weiss
email :      josef -at- josefweiss.com
url :        http://josefweiss.com

"""


import requests
import json
import logging
import sys
import os
import datetime


class SecurityCenter:
    """
    Class to handle connections to a SecurityCenter server. Performs
    login, logout, and sends API requests to the server. Server
    responses are parsed and the content of the response is sent to
    the calling method.
    """

    def __init__(self, server, verify_ssl=False):
        self._server = server
        self._verify = verify_ssl
        self._token = ''
        self._cookie = ''
        #self._log = logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
        self._log = logging.getLogger('scapy')

    def authenticated(self):
        """
        Determine whether we are authenticated to the server.

        If the self._token is not empty then we are authenticated otherwise we
        are not.
        """
        if self._token == '':
            return False
        else:
            return True

    def login(self, username, password):
        """
        Login to the SecurityCenter server and set the token.

        Send a POST request to the token endpoint with the username and
        password. If the authentication request was successful, the server
        will return a token that must be sent in the Authentication header of
        all subsequent requests.
        """
        input = {'username': username, 'password': password}
        resp = self.connect('POST', 'token', input)

        if resp is not None:
            self._token = resp['token']

    def logout(self):
        """
        Logout of the SecurityCenter server.

        Send a DELETE request to the token endpoint and delete the stored
        token and cookie.
        """
        self.connect('DELETE', 'token')
        self._token = ''
        self._cookie = ''

    def connect(self, method, resource, data=None):
        """
        Send a request to SecurityCenter server.

        Use the method, resource and data to build a request to send to the
        SecurityCenter server. If the session token and cookie are available,
        add them to the request headers. Also specify the content-type as JSON
        and check for any errors in the response. If there are no errors,
        return the SecurityCenter response. If there are errors, log them and
        return None.
        """
        headers = {
            'Content-Type': 'application/json',
        }

        if self._token != '':
            headers['X-SecurityCenter'] = self._token

        if self._cookie != '':
            headers['Cookie'] = self._cookie

        # Only convert the data to JSON if there is data.
        if data is not None:
            data = json.dumps(data)

        url = "https://{0}/rest/{1}".format(self._server, resource)

        self._log.debug('Making {0} request to {1}'.format(method, resource))

        try:
            if method == 'POST':
                r = requests.post(url, data=data, headers=headers, verify=self._verify)
            elif method == 'PUT':
                r = requests.put(url, data=data, headers=headers, verify=self._verify)
            elif method == 'PATCH':
                r = requests.patch(url, data=data, headers=headers, verify=self._verify)
            elif method == 'DELETE':
                r = requests.delete(url, data=data, headers=headers, verify=self._verify)
            else:
                r = requests.get(url, params=data, headers=headers, verify=self._verify)

        except requests.ConnectionError, e:
            self._log.error(str(e))
            return None

        self._log.debug('Request Headers: {0}'.format(r.request.headers))
        self._log.debug('Request Data: {0}'.format(r.request.body))
        self._log.debug('Response Headers: {0}'.format(r.headers))
        self._log.debug('Response Data: {0}'.format(r.content))

        if r.headers.get('set-cookie') is not None:
            self._cookie = r.headers.get('set-cookie')

        # Make sure we have a JSON response. If not then return None.
        try:
            contents = r.json()
        except ValueError as e:
            self._log.error(e)
            return None

        # If the response status is not 200 OK, there is an error.
        if contents['error_code'] != 0:
            self._log.error(contents['error_msg'])
            return None

        # Return the contents of the response field from the SecurityCenter
        # response.
        return contents['response']

    def upload(self, filename, rc=None, context=None, fs=None):
        """
        Upload the given file to the SC server.
        """
        headers = {
            'X-SecurityCenter': self._token,
            'Cookie': self._cookie
        }

        params = {}

        files = {'Filedata': (os.path.basename(filename), open(filename, 'rb'), 'application/octet-stream')}

        if context is not None:
            params['context'] = context

        if rc is not None:
            files['returnContent'] = rc

        if fs is not None:
            files['MAX_FILE_SIZE'] = int(fs)

        url = "https://{0}/rest/file/upload".format(self._server)

        self._log.debug('Uploading file {0}.'.format(filename))

        try:
            r = requests.post(url, headers=headers, params=params, files=files, verify=self._verify)

        except requests.ConnectionError, e:
            self._log.error(str(e))
            return None

        self._log.debug('Request Headers: {0}'.format(r.request.headers))
        self._log.debug('Request Data: {0}'.format(r.request.body))
        self._log.debug('Response Headers: {0}'.format(r.headers))
        self._log.debug('Response Data: {0}'.format(r.content))

        # Make sure we have a JSON response. If not then return None.
        try:
            contents = r.json()
        except ValueError as e:
            self._log.error(e)
            return None

        # If the response status is not 200 OK, there is an error.
        if contents['error_code'] != 0:
            self._log.error(contents['error_msg'])
            return None

        # Return the filename given by SecurityCenter
        return contents['response']['filename']

    def analysis(self, query, limit=sys.maxint - 1):
        """
        Queries the SC server for a list of vulnerabilities or events that
        match the given parameters. The SC server is queried for results in
        groups of 1000. Yields results that match the parameters or None if
        there is an error. Returns no more than limit results.
        """

        received = 0
        step = 1000
        query['startOffset'] = 0
        query['endOffset'] = 0
        total = limit

        if query.get('id') is not None:
            input = {'type': 'vuln',
                     'sourceType': 'cumulative',
                     'query': query}
        else:
            input = {'type': query['type'],
                     'sourceType': query['subtype'],
                     'query': query}

        while (received < limit) and (received < total):

            # If my endOffset is larger than max, set it to max.
            if received + step > limit:
                query['endOffset'] = limit
            else:
                query['endOffset'] += step

            """
            For additional troubleshooting, you can uncomment the following two lines of code.
            Uncommenting them will display the QUERY and INPUT strings in the output
            """
            #print 'QUERY:\n{0}\n'.format(query)
            #print 'INPUT:\n{0}\n'.format(input)

            response = self.connect('POST', 'analysis', input)

            # There is an error
            if response is None:
                received = limit + 1
                continue

            # process the returned records
            received += response['returnedRecords']
            total = int(response['totalRecords'])
            self._log.debug('Received {0} of {1} records.'.format(received,
                             total))

            for v in response['results']:
                yield v

            query['startOffset'] = query['endOffset']


if __name__ == '__main__':

    logging.getLogger('requests').setLevel(logging.WARNING)
    requests.packages.urllib3.disable_warnings()

    """
    Configure the login details for SecurityCenter here.  You are required to
    input the IP or FQDN for SecurityCenter, the username and password for the
    account that you wish to use.

    Example sc = SecurityCenter('sc.mydomain.com')  or sc = SecurityCenter('192.168.1.1')
            sc.login('bob', 'abc123')
    """
    sc = SecurityCenter('SecurityCenterIP_Goes_Here')
    sc.login('loginName', 'password')

    if sc.authenticated():

        resp = sc.connect('GET', 'query')
        # Uncomment the following line to view the entire response in the output.
        # print resp

        """
        This section will conduct a vulnerability query and display:
        1. The IP address
        2. Plugin name
        3. Plugin ID
        4. Solution
        for the first 10 critical vulnerabilities.  A value of 4=Critical, 3=High, 2=Medium, 1=Low
        """
        print
        print
        filters = [{'filterName': 'severity',
                    'operator': '=',
                    'value': '4',
                    }]

        query = {'type': 'vuln',
                 'tool': 'vulndetails',
                 'subtype': 'cumulative',
                 'filters': filters}

        for v in sc.analysis(query, limit=10):
            print 'IP: ' +v['ip']
            print 'Name: ' +v['pluginName']
            print 'Plugin ID: ' +v['pluginID']
            print 'Solution: ' +v['solution']
            print

        """
        Call to logout
        """


        sc.logout()

