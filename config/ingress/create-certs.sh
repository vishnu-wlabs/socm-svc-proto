#!/bin/sh
read -p 'Enter server name: ' server_name
sudo rm -rf certs
mkdir certs
openssl genrsa -out certs/${server_name}.key 2048
openssl req -new -key certs/${server_name}.key -out certs/${server_name}.csr
openssl x509 -req -days 365 -in certs/${server_name}.csr -signkey certs/${server_name}.key -out certs/${server_name}.crt
rm -f certs/${server_name}.csr
