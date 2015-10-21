# '''
# @author: liyankun
# '''
import copy
import boto
import boto.s3.connection
access_key = '11111111'
secret_key = '11111111'
 
conn = boto.connect_s3(
        aws_access_key_id = access_key,
        aws_secret_access_key = secret_key,
        host = '10.0.3.70',
        port = 7480,
        #is_secure=False,               # uncomment if you are not using ssl
        calling_format = boto.s3.connection.OrdinaryCallingFormat(),
        )
# print conn.get_all_buckets()
print dir(conn)


# import sys
# import hmac
# import base64
# 
# from logging import debug
# 
# from hashlib import sha1, sha256
# 
# __all__ = []
# 
# ### AWS Version 2 signing
# def sign_string_v2(string_to_sign, secret_key):
#     """Sign a string with the secret key, returning base64 encoded results.
#     By default the configured secret key is used, but may be overridden as
#     an argument.
# 
#     Useful for REST authentication. See http://s3.amazonaws.com/doc/s3-developer-guide/RESTAuthentication.html
#     """
#     signature = base64.encodestring(hmac.new(secret_key, string_to_sign, sha1).digest()).strip()
#     return signature

import requests
import logging
from awsauth import S3Auth
import json
from boto.dynamodb.condition import NULL

ACCESS_KEY = "11111111"
SECRET_KEY = "11111111"
# ACCESS_KEY = "f2622c12ade9472785cddc700c673d0f"
# SECRET_KEY = "8bc18585990347e48b21ba658f824db1"
SERVER = "10.0.3.70:7480"
ENDPOINT = "http://10.0.3.70:7480/admin/"

def pre_params(params):
    pass

def init_url(params):
    global ENDPOINT
    url = "%s%s%s" %(ENDPOINT, params,"format=json")
    print url
    return url

def init_url_no_format(params):
    global ENDPOINT
    url = "%s%s" %(ENDPOINT, params)
    print url
    return url

def get_auth(access_key=None, secret_key=None, server=None):
    global ACCESS_KEY, SECRET_KEY, SERVER
    
    if not access_key:
        access_key = ACCESS_KEY
    if not secret_key:
        secret_key = SECRET_KEY
    if not server:
        server = SERVER
    
    return S3Auth(access_key, secret_key, server)
        
def create_user_old(params):
    url = "http://10.0.3.70:7480/admin/user?uid=aaaaaa&display-name=aaaaaa&format=json"
#     url = init_url(params)
#     opt = {
#            'uid': uid,
#            'email': email,
#            'access-key': access_key,
#            'secret-key': secret_key,
#            'display-name': 'test'
#            }    
    r = requests.put(url, auth=S3Auth('11111111', '11111111', '10.0.3.70:7480'))
#     data = json.load(r.content)
    print json.dumps(r.content)
    
def get_usage(uid, access_key, secret_key):
    url = "http://10.0.3.70:7480/admin/usage?format=json"
    r = requests.get(url,auth=S3Auth(access_key, secret_key, '10.0.3.70:7480'))
    print json.loads(r.content)
#     print json.dumps(r.content)

    
def trim_usage(params):
    url = init_url(params)
    result = requests.get(url, auth=get_auth())
    return result.content
    
    
def get_user_info(params):
    url = init_url(params)
    result = requests.get(url, auth=get_auth())
    return result.content

def modify_user(params):
    url = init_url(params)
    result = requests.post(url, auth=get_auth())
    return result.content

def create_user(params):
    url = init_url(params)
    result = requests.put(url, auth=get_auth())
    return result.content

def remove_user(params):
    url = init_url(params)
    result = requests.delete(url, auth=get_auth())
    return result.content

def create_key(params):
    url = init_url(params)
    result = requests.put(url, auth=get_auth())
    return result.content

def remove_key(params):
    url = init_url(params)
    result = requests.delete(url, auth=get_auth())
    return result.content

def get_bucket_info(params):
    url = init_url(params)
    result = requests.get(url, auth=get_auth())
    return result.content

def check_bucket_index(params):
    url = init_url(params)
    result = requests.get(url, auth=get_auth())
    return result.content

def remove_bucket(params):
    url = init_url(params)
    result = requests.delete(url, auth=get_auth())
    return result.content

def link_bucket(params):
    url = init_url(params)
    result = requests.put(url, auth=get_auth())
    return result.content

def unlink_bucket(params):
    url = init_url(params)
    result = requests.post(url, auth=get_auth())
    return result.content 

def remove_object(params):
    url = init_url(params)
    result = requests.delete(url, auth=get_auth())
    return result.content

def get_bucket_or_object_policy(params):
    url = init_url(params)
    result = requests.get(url, auth=get_auth())
    return result.content

def add_user_capability(params):
    url = init_url(params)
    result = requests.put(url, auth=get_auth())
    return result.content

def remove_user_capability(params):
    url = init_url(params)
    result = requests.delete(url, auth=get_auth())
    return result.content

def get_user_quota(params):
    url = init_url_no_format(params)
    result = requests.get(url, auth=get_auth())
    return result

def set_user_quota(params):
#     url = init_url_no_format(params)
    url = init_url(params)
    data = {
            'max-objects': 999,
#             'quota-scope': 'bucket'
#             'quota-type': 'bucket',
#             'max-size': 699,
#             'enable': True
            }
    headers = copy.deepcopy(data)
#     data = dict(quota-scope=)
#     requests.header['content-type'] = "application/json"
#     result = requests.put(url, auth=get_auth(), data=json.dumps(data))
    result = requests.put(url, auth=get_auth())
    return result
# def set_user_quota(params):
#     url = "http://10.0..70:7480/admin/user?quota&uid=aaaaaa&quota-type=user"
#     data = {
#             'max-objects': 999,
#             'quota-scope': 'user',
#             'max-size': 10000
#             }
#     result = requests.put(url, auth=S3Auth('11111111', '11111111', '10.0.3.70:7480'), data=json.dumps(data))
#     return result

def enable_user_quota(params):
    url = init_url(params)
    result = requests.get(url, auth=get_auth())
    return result.content

def enable_bucket_quota(params):
    url = init_url(params)
    result = requests.get(url, auth=get_auth())
    return result.content

def get_bucket_quota(params):
    url = init_url(params)
    result = requests.get(url, auth=get_auth())
    return result.content
def set_bucket_quota(params):
    url = init_url(params)
    data = {
            'max_objects': 10,
            'max_size_kb': 999,
            'enabled': True
            }
    result = requests.put(url,data=json.dumps(data), auth=get_auth())
    return result

def admin_operate_api(params):
    url = init_url(params)
    result = requests.get(url, auth=get_auth())
    return result.content

if "__main__" == __name__:
    #create user
#     params = "user?uid=wwwwww&display-name=wwwwww&email=456732434@qq.com&user-caps=users=read;usage=read,write&"
#     create_user(params)
    #admin api operations
#     create_user('xxxxxx', 'xxxxxx', 'xxxxxx', 'xxxxxx@qq.com')
#     get_usage("", '11111111', '11111111')
#     trim_usages = "usage?"
#     print trim_usage("usage")
    #get user info
#     user_info = "user?uid=111111&"
#     print get_user_info(user_info)
    #modify user
#     modify_users = "user?uid=aaaaaa&max-buckets=500&" 
#     print modify_user(modify_users)
    #create user
#     user_info = "user?uid=qqqqqqs&display-name=444444s&email=qqqqqqs@qq.com&key-type=s3&access-key=qqqqqqqqs&secret-key=qqqqqqqq&user-caps=users=read&"
#     print create_user(user_info)
    #remove user
#     params = "user?uid=qqqqqqs&"
#     print remove_user(params)
    #create key
#     params = "user?key&uid=qqqqqq&key-type=s3&access-key=wwwwwwww&secret-key=wwwwwwww&"
#     print create_key(params)
    #remove key
#     params = "user?key&access-key=wwwwwwww&"
#     print remove_key(params)
    #get bucket info
#     params = "bucket?bucket=uuuuu&"
#     print get_bucket_info(params)
    #check bucket index
#     params = "bucket?index&bucket=uuuuu&"
#     print check_bucket_index(params)
    #remove bucket
#     params = "bucket?bucket=uuuuu&"
#     print remove_bucket(params)  
    #link bucket
#     params = "bucket?bucket=uuuuuu&uid=qqqqqq&"
#     print link_bucket(params)
    #unlink_bucket
#     params = "bucket?bucket=uuuuuu&uid=qqqqqq&"
#     print unlink_bucket(params)
    #remove object 
#     params = "bucket?object&bucket=uuuuuu&object=xxx.txt"
#     print remove_bucket(params)
    #get bucket or object policy
#     params = "bucket?policy&bucket=uuuuuu&"
#     print get_bucket_or_object_policy(params)
    #add a user capability
#     params = "user?caps&uid=qqqqqq&user-caps=users=read&"
#     print add_user_capability(params)

    #remove caps from user
#     params = "user?caps&uid=qqqqqq&user-caps=users=read&"
#     print remove_user_capability(params)
    
    #set user quota
#     params = "user?quota&uid=111111&quota-type=bucket&&max-objects=4444&"
#     re = set_user_quota(params)
#     print "re.text: %s" % re.text
#     print "re.headers: %s" % re.headers
#     print "re.content: %s" % re.content
#     print "re: %s" % re
#     get user quota
#      params = "user?quota&uid=111111&quota-type=bucket"
#      re = get_user_quota(params)
#      print "headers : %s" % re.headers
#      print "json : %s" % re.json
#      print "raw : %s" % re.raw
#      print "request : %s" % re.request
#      print "content : %s" % re.content
#      print "text : %s" % re.text
    
    #enable user quota
#     params = "user?quota&uid=qqqqqq&quota-type=user&"
#     print enable_user_quota(params)
    #set bucket quota
#     params = "user?quota&uid=aaaaaa&quota-type=bucket&max-objects=2000"
#     re = set_bucket_quota(params)
#     print re.headers
#     print re
