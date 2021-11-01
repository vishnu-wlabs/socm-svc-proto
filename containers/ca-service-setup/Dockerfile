FROM vault:latest

RUN apk add --update curl && apk add --update jq

COPY vaultrun.sh /usr/local/bin/vaultrun.sh
COPY unseal.sh /usr/local/bin/unseal.sh
COPY setup-ca.sh /usr/local/bin/setup-ca.sh

RUN chmod +x /usr/local/bin/vaultrun.sh
RUN chmod +x /usr/local/bin/unseal.sh
RUN chmod +x /usr/local/bin/setup-ca.sh

ENTRYPOINT '/usr/local/bin/vaultrun.sh'