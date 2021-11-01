#!/bin/sh
read -p 'Enter server name: ' server_name
cd certs
openssl genrsa -out ${server_name}.key 2048
openssl req -new -key ${server_name}.key -out ${server_name}.csr
openssl x509 -req -days 365 -in ${server_name}.csr -signkey ${server_name}.key -out ${server_name}.crt
rm -f ${server_name}.csr
cd ..