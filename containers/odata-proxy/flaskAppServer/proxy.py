from flask import Blueprint,Response,request, jsonify, make_response
import json
import requests
import logging
import datetime
import os

import jwt
import requests

from flaskAppServer.authenticate import token_required
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from functools import wraps
from flaskAppServer.patch import patch_requests

bp = Blueprint('proxy',__name__,url_prefix='/')

VAULT_ENDPOINT = 'http://ca-service:8200/v1/pki_int/issue/client_certs'
VAULT_AUTH_ENDPOINT = 'http://ca-service:8200/v1/auth/jwt/login'
SAP_ENDPOINT = os.environ['SAP_ENDPOINT']


@bp.route('/<path:path>',methods=['GET','POST','DELETE'])
@token_required #Verify token decorator
def proxy(access_token,current_user,path):
    #authenticate with JWT

    auth_payload = json.dumps({
        "role": "jwt_client_cert",
        "jwt": access_token
    })
    auth_headers = {
        'Content-Type': 'application/json'
    }

    auth_response = requests.request("POST", VAULT_AUTH_ENDPOINT, headers=auth_headers, data=auth_payload)
    vault_token = auth_response.json()['auth']['client_token']

    payload = json.dumps({
        "common_name": current_user['upn'].rsplit('@')[0]
    })
    headers = {
        'X-Vault-Token': vault_token,
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", VAULT_ENDPOINT, headers=headers, data=payload)

    #app.logger.info('%s logged in successfully', response.json())

    cert = response.json()['data']['certificate']
    pvk = response.json()['data']['private_key']
    pvk_typ = response.json()['data']['private_key_type']

    x509_cert = load_pem_x509_certificate(cert.encode(), default_backend())
    cert_key = serialization.load_pem_private_key(pvk.encode(), None, default_backend())
    endpoint = SAP_ENDPOINT

    patch_requests()

    excluded_proxy_headers = ['Authorization', 'Host','Agent','Postman-Token','Connection']
    resp = requests.request(
        method=request.method,
        url=request.url.replace(request.host_url, endpoint),
        headers={key: value for (key, value) in request.headers if key not in excluded_proxy_headers},
        data=request.get_data(),
        allow_redirects=False,
        cert=(x509_cert,cert_key),
        cookies=request.cookies,
        verify=False
    )
    excluded_resp_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items()
               if name.lower() not in excluded_resp_headers]

    response = Response(resp.content, resp.status_code, headers)
    return response