import json
import requests
import datetime
import os
from authenticate import token_required #The token verification script
from flask import Flask, request,Response
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
import requests
from patch import patch_requests

app = Flask(__name__)



app.config['VAULT_ENDPOINT'] = 'http://ca-service:8200/v1/pki_int/issue/client_certs'
app.config['SAP_ENDPOINT'] = os.environ['SAP_ENDPOINT']
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False


@app.route('/<path:path>',methods=['GET','POST','DELETE'])
@token_required #Verify token decorator
def proxy(current_user,path):

    root_sec = open("/mnt/secrets/root_token.sec", "r")
    root_token = root_sec.readline().strip("\t").strip("\n")
    root_sec.close()

    payload = json.dumps({
        "common_name": current_user['upn'].rsplit('@')[0],
        "ttl": "8h"
    })
    headers = {
        'X-Vault-Token': root_token,
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", app.config['VAULT_ENDPOINT'], headers=headers, data=payload)

    #app.logger.info('%s logged in successfully', response.json())

    cert = response.json()['data']['certificate']
    pvk = response.json()['data']['private_key']
    pvk_typ = response.json()['data']['private_key_type']

    x509_cert = load_pem_x509_certificate(cert.encode(), default_backend())
    cert_key = serialization.load_pem_private_key(pvk.encode(), None, default_backend())
    endpoint = app.config['SAP_ENDPOINT']

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

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port=5001)