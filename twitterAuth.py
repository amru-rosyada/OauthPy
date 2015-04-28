# twitterAuth
# usage :
# oauth = TwitterAuth(consumer_secret, consumer_key)
# oauth.request_token() # for request token
# oauth.do_request() # if you want to implement other request just use this one and wrap arround
import time
from base64 import b64encode
from urllib.parse import quote, parse_qs
from urllib.request import Request, urlopen
from hmac import new as hmac
from hashlib import sha1

class TwitterAuth():
    
    # constructor init parameter is consumer secret and consumer key
    def __init__(self, consumer_secret, consumer_key):
        self.consumer_secret = consumer_secret
        self.consumer_key = consumer_key
        
        # list of dictionary of twitter rest api url
        # access via dicionary get will return url of rest api
        # ex: twitter_rest_api.get('api_authenticate')
        self.twitter_rest_api = {'api_authenticate':'https://api.twitter.com/oauth/authenticate',
            'api_request_token':'https://api.twitter.com/oauth/request_token',
            'api_access_token':'https://api.twitter.com/oauth/access_token',
            'api_statuses_user_timeline':'https://api.twitter.com/1.1/statuses/user_timeline.json'}

    # parameter
    # url_request : api url for request ex https://api.twitter.com/oauth/request_token
    # oauth_token : access token for accessing api this step should be after request granting from user to application
    # oauth_token_secret : access token will concate with consumer secret for generating signing key
    # oauth_callback : required if request oauth token and oauth token sercret, this callback should be same with application callback on api provider
    # request_method can be POST/GET
    # use_headers_auth False/True, depend on provider restriction
    # if use_headers_auth True headers will send with Authorization payload
    # additional_params should be pair key and val as dictionary and will put on payload request
    def do_request(self, url_request='', request_method='GET',
        oauth_token='', oauth_token_secret='',
        oauth_callback='', use_headers_auth=False, additional_params={}):

        oauth_nonce = str(time.time()).replace('.', '')
        oauth_timestamp = str(int(time.time()))

        params = {'oauth_consumer_key':self.consumer_key,
            'oauth_nonce':oauth_nonce,
            'oauth_signature_method':'HMAC-SHA1',
            'oauth_timestamp':oauth_timestamp,
            'oauth_version':'1.0'}

        # if validate callback
        # and request token and token secret
        if(oauth_callback != ''):
            params['oauth_callback'] = oauth_callback

        # if request with token
        if(oauth_token != ''):
            params['oauth_token'] = oauth_token

        # check if additional_params length != 0
        # append additional param to params
        if(len(additional_params)):
            for k in additional_params:
                params[k] = additional_params[k]

        # create signing key
        # generate oauth_signature
        # key structure oauth standard is [POST/GET]&url_request&parameter_in_alphabetical_order
        params_str = '&'.join(['%s=%s' % (self.percent_quote(k), self.percent_quote(params[k])) for k in sorted(params)])
        message = '&'.join([request_method, self.percent_quote(url_request), self.percent_quote(params_str)])

        # Create a HMAC-SHA1 signature of the message.
        # Concat consumer secret with oauth token secret if token secret available
        # if token secret not available it's mean request token and token secret
        key = '%s&%s' % (self.percent_quote(self.consumer_secret), self.percent_quote(oauth_token_secret)) # Note compulsory "&".
        print(key)
        signature = hmac(key.encode('UTF-8'), message.encode('UTF-8'), sha1)
        digest_base64 = b64encode(signature.digest()).decode('UTF-8')
        params["oauth_signature"] = digest_base64

        # this is parameter should be pass into url_request
        params_str = '&'.join(['%s=%s' % (self.percent_quote(k), self.percent_quote(params[k])) for k in sorted(params)])

        # if use_headers_auth
        headers_payload = {}
        if use_headers_auth:
            headers_str_payload = 'OAuth ' + ', '.join(['%s="%s"' % (self.percent_quote(k), self.percent_quote(params[k])) for k in sorted(params)])
            headers_payload['Authorization'] = headers_str_payload

            # if POST method add urlencoded
            if request_method == 'POST':
                headers_payload['Content-Type'] = 'application/x-www-form-urlencoded'
                
            headers_payload['User-Agent'] = 'HTTP Client'

        # request to provider with
        # return result
        try:
            req = Request(url_request, data=params_str.encode('ISO-8859-1') ,headers=headers_payload)
            res = urlopen(req)
            return res.readall()
        except Exception as e:
            print(e)
            return None

    # simplify request token
    # get request token
    # required oauth_callback
    def request_token(self, oauth_callback):
        res = self.do_request(url_request=self.twitter_rest_api.get('api_request_token'),
            request_method='POST',
            oauth_callback=oauth_callback,
            use_headers_auth=True)

        # mapping to dictionary
        # return result as dictioanary
        if res:
            res = parse_qs(res.decode('UTF-8'))
            data_out = {}
            for k in res:
                data_out[k] = res[k][0]

            return data_out
            

        # default return is None
        return None

    # request authentication url
    # requred parameter is oauth_token
    # will return request_auth_url for granting permission
    def request_auth_url(self, oauth_token):
        if oauth_token:
            return '?'.join((self.twitter_rest_api.get('api_authenticate'), '='.join(('oauth_token', self.percent_quote(oauth_token)))))
            
        # default value is None
        return None
        
    # request access token
    # parameter oauth_verifier and oauth_token is required 
    def request_access_token(self, oauth_token, oauth_verifier):
        if oauth_token and oauth_verifier:
            res = self.do_request(url_request=self.twitter_rest_api.get('api_access_token'),
                request_method='POST',
                oauth_token=oauth_token,
                oauth_token_secret='',
                oauth_callback='',
                use_headers_auth=True,
                additional_params={'oauth_verifier':oauth_verifier})
                
            # mapping to dictionary
            # return result as dictioanary
            if res:
                res = parse_qs(res.decode('UTF-8'))
                data_out = {}
                for k in res:
                    data_out[k] = res[k][0]
    
                return data_out
                
        # default return none
        return None
        
    # get statuses user timeline
    # Returns a collection of the most recent Tweets posted by the user indicated by the screen_name or user_id parameters.
    # optional params={'user_id':'117257387', 'screen_name':'_mru_', 'since_id':'',
    #   'count':'', 'max_id':'', 'trim_user':'', 'exclude_replies':'', 'contributor_details':'', 'include_rts':''}
    # oauth_token and oauth_token_secret is required
    def request_statuses_user_timeline(self, oauth_token, oauth_token_secret, params={}):
        
        res = self.do_request(url_request=self.twitter_rest_api.get('api_statuses_user_timeline'),
                request_method='GET',
                oauth_token=oauth_token,
                oauth_token_secret=oauth_token_secret,
                oauth_callback='',
                use_headers_auth=True,
                additional_params=params)
                
        return res

    # percent_quote
    # quote url as percent quote
    def percent_quote(self, text):
        return quote(text, '~')

# testing outh request token
oauth = TwitterAuth('YOUR CONSUMER SECRET', 'YOUR CONSUMER KEY')
#res = oauth.request_token(oauth_callback='http://127.0.0.1:8888/p/authenticate/twitter')
#print(oauth.request_auth_url(res.get('oauth_token')))
#oauth_token=KYo6CvkJfY7lFAvezEyb0OzThyFI2Dx5&oauth_verifier=JD72yzulrPqhT0FKfE70g14eNCIeHKfW
access_token = oauth.request_access_token('KYo6CvkJfY7lFAvezEyb0OzThyFI2Dx5', 'JD72yzulrPqhT0FKfE70g14eNCIeHKfW')
print(oauth.request_statuses_user_timeline(access_token['oauth_token'], access_token['oauth_token_secret']))