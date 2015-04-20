# facebookAuth is implementation of auth facebook opengraph API
# usage :
# oauth = OAuth(consumer_secret, consumer_key)
# oauth.request_token() # for request token
# oauth.do_request() # if you want to implement other request just use this one and wrap arround
import time
from base64 import b64encode
from urllib.parse import quote, parse_qs
from urllib.request import Request, urlopen
from hmac import new as hmac
from hashlib import sha1

class facebookAuth():
    
    # constuctor
    # param is app_id and app_secret from facebook
    def __init__(self, app_id, app_secret):
        # for non standard oauth like facebook
        self.app_id = app_id
        self.app_secret = app_secret

    # not using standard oauth
    # url_request : url request to api
    # request_method : GET/POST
    # params : must be pair key value {key:value. key:value} and will be passed when request
    # ex :
    # params = {'grant_type'='client_credentials, 'callback'='http://localhost/auth/fb'}
    def do_request(self, url_request='', request_method='GET', params={}):
        
        # define headers payload
        # define user agent
        headers_payload = {'User-Agent':'HTTP Client'}
        if request_method == 'POST':
            headers_payload['Content-Type'] = 'application/x-www-form-urlencoded'
        
        # parameter list
        params_str = '&'.join(['%s=%s' % (k, self.percent_quote(params[k])) for k in sorted(params)])
            
        # request to provider
        # return result
        try:
            req = Request(url_request, data=params_str.encode('ISO-8859-1'), headers=headers_payload)
            res = urlopen(req)
            return res.readall()
        except Exception as e:
            print(e)
            return None
            
    # request token
    def request_token(self, url_request, grant_type='client_credentials', request_method='GET'):
        params = {'client_id':self.app_id,
            'client_secret':self.app_secret,
            'grant_type':grant_type}
        
        return self.do_request(url_request=url_request, request_method='GET', params=params).decode('UTF-8')
        

    # percent_quote
    # quote url as percent quote
    def percent_quote(self, text):
        return quote(text, '~')
        
auth = facebookAuth('YOUR APP ID', 'YOUR APP SECRET')
print(auth.request_token('https://graph.facebook.com/oauth/access_token'))