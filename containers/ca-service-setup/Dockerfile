FROM alpine:3.14

RUN apk add --update curl jq vault libcap 
RUN setcap cap_ipc_lock= /usr/sbin/vault

RUN mkdir /policies

COPY vaultrun.sh /usr/local/bin/vaultrun.sh
COPY unseal.sh /usr/local/bin/unseal.sh
COPY setup-ca.sh /usr/local/bin/setup-ca.sh
COPY *.hcl /policies/

RUN chmod +x /usr/local/bin/vaultrun.sh
RUN chmod +x /usr/local/bin/unseal.sh
RUN chmod +x /usr/local/bin/setup-ca.sh

CMD ["sh", "/usr/local/bin/vaultrun.sh"]