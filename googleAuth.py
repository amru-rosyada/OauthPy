# googleAuth is implementation of google authentication
# usage :
# oauth = GoogleAuth(client_secret, client_id)
# oauth.request_token() # for request token
# oauth.do_request() # if you want to implement other request just use this one and wrap arround
import time
from base64 import b64encode
from urllib.parse import quote, parse_qs
from urllib.request import Request, urlopen
from hmac import new as hmac
from hashlib import sha1

class GoogleAuth():
    
    # constructor init parameter is client secret and client id
    def __init__(self, client_secret, client_id):
        self.client_id = client_id
        self.client_secret = client_secret
        
    # do request
    # url_request : url to googple api
    # request_method : can be GET/POST
    # params : is pair key and value that will be pass to url_request
    # ex : params = {'client_id':'', 'client_secret'='', 'other param':''}
    # params wil be generated into client_id=''&client_secret=''&other_param=''
    # return_url_only=True, if value True will only return url access without request and method must be GET
    def do_request(self, url_request, request_method='GET', params={}, return_url_only=True):
        # generate params depend on param to be passed
        params_str = '&'.join(['%s=%s' % (k, self.percent_quote(params[k])) for k in sorted(params)])
        
        headers_payload = {'User-Agent':'HTTP Client'}
        # if POST method add urlencoded
        if request_method == 'POST':
            headers_payload['Content-Type'] = 'application/x-www-form-urlencoded'
        
        # if return url only return get url
        if return_url_only:
            return url_request + '?' + params_str
        
        # do request
        # if not return url only do request and return result value
        try:
            req = Request(url_request, params_str.encode('ISO-8859-1'), headers=headers_payload)
            res = urlopen(req)
            return res.readall()
        except Exception as e:
            print(e)
            return None
        
    # get request_auth_url
    # url_request : api url request from google open id connect
    # redirect_uri : page redirection after access granted
    def request_auth_url(self, url_request, redirect_uri):
        params = {'client_id':self.client_id,
            'response_type':'code',
            'scope':'profile https://www.googleapis.com/auth/plus.login email https://www.googleapis.com/auth/plus.profile.emails.read openid https://www.googleapis.com/auth/plus.me',
            'redirect_uri':redirect_uri,
            'state':str(time.time()).replace('.', ''),
            'include_granted_scopes':'true'}
            
        return self.do_request(url_request=url_request, params=params, return_url_only=True)
        
        
    # percent quote
    # parameter is text tobe percent quoted
    def percent_quote(self, text):
        return quote(text, '~')
        
auth = GoogleAuth('YOUR CLIENT ID', 'YOUR CLIENT SECRET')
print(auth.request_auth_url('https://accounts.google.com/o/oauth2/auth', 'http://localhost:8888/p/authenticate/google'))