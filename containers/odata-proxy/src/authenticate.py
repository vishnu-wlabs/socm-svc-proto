import json
import jwt
import os
import requests
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from flask import Flask, request, jsonify, make_response
from functools import wraps


APP_ID      = os.environ['AZURE_APPID']
JWKS_URI    = os.environ['AZURE_JWKSURI']
ISS         = os.environ['AZURE_ISSUER']

# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            access_token = str.replace(str(token), 'Bearer ', '')
            current_user = validate_token(access_token)
        
        except jwt.exceptions.ExpiredSignatureError:
            return jsonify({'message' : 'Expired Token'}), 401
        except jwt.exceptions.InvalidAudienceError:
            return jsonify({'message' : 'Invalid Audience'}), 401
        #except Exception as e:
        #    return jsonify({'message' : 'Server Internal Error '}), 502
        

        # returns the current logged in users contex to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated

def validate_token(access_token):
    access_token_header = jwt.get_unverified_header(access_token)
    res = requests.get(JWKS_URI)
    jwk_keys = res.json()

    x5c = None

    # Iterate JWK keys and extract matching x5c chain
    for key in jwk_keys['keys']:
        if key['kid'] == access_token_header['kid']:
            x5c = key['x5c']

    cert = ''.join([
        '-----BEGIN CERTIFICATE-----\n',
        x5c[0],
        '\n-----END CERTIFICATE-----\n',
    ])
    public_key = load_pem_x509_certificate(cert.encode(), default_backend()).public_key()

    token = jwt.decode(
        access_token,
        public_key,
        algorithms='RS256',
        audience=APP_ID,
        options={"require": ["exp", "iss", "sub"]}
    )

    current_user = {
                    "family_name": token['family_name'],
                    "given_name": token['given_name'],
                    "ipaddr": token['ipaddr'],
                    "oid": token['oid'],
                    "sub": token['sub'],
                    "unique_name": token['unique_name'],
                    "upn": token['upn']

                }

    return current_user


