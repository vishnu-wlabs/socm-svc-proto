FROM nginx:1.19.1-alpine
ARG CERT_SUBJECT="/CN=localhost"
ENV WWW_DIR /var/www

RUN apk update && \
    apk add --no-cache openssl && \
    openssl req -x509 -nodes -days 365 \
    -subj $CERT_SUBJECT \
     -newkey rsa:2048 -keyout /etc/ssl/private/socm.key \
     -out /etc/ssl/certs/socm.crt;

COPY root/* ${WWWW_DIR}/
COPY nginx.conf /etc/nginx/nginx.conf
