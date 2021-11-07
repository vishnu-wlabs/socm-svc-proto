#!/bin/sh
#CA Setup - run only if CA is not initialized


pki_stat=`curl -k -s -o /tmp/http_stat.out -w "%{http_code}" $VAULT_ADDR/v1/pki/ca/pem`

if [[ $pki_stat != '200' ]]; then
     root_token=`cat /mnt/secrets/root_token.sec`
     vault login ${root_token} > /dev/null
     vault secrets enable pki
     vault secrets tune -max-lease-ttl=87600h pki
     vault write -field=certificate pki/root/generate/internal \
          common_name="${ROOTCA_CN}" \
          ou="${OU}" \
          organization="${ORG}" \
          country="US" \
          ttl=87600h > /dev/null
     vault write pki/config/urls \
          issuing_certificates="$VAULT_ADDR/v1/pki/ca" \
          crl_distribution_points="$VAULT_ADDR/v1/pki/crl"


     #Inter CA Setup
     vault secrets enable -path=pki_int pki
     vault secrets tune -max-lease-ttl=43800h pki_int

     vault write -format=json pki_int/intermediate/generate/internal \
          common_name="${SUBCA_CN}" \
          ou="${OU}" \
          organization="${ORG}" \
          country="US" \
          | jq -r '.data.csr' > /tmp/pki_intermediate.csr

     vault write -format=json pki/root/sign-intermediate \
                    csr=@/tmp/pki_intermediate.csr format=pem_bundle ttl="43800h" \
                    |jq -r '.data.certificate' > /tmp/socm-interca.pem


     vault write pki_int/intermediate/set-signed \
                    certificate=@/tmp/socm-interca.pem

     vault write pki_int/config/urls \
          issuing_certificates="$VAULT_ADDR/v1/pki_int/ca" \
          crl_distribution_points="$VAULT_ADDR/v1/pki_int/crl"

     #Create a role
     vault write pki_int/roles/client_certs \
          allow_any_name=true \
          client_flag=true \
          server_flag=false \
          no_store=true \
          ou="${OU}" \
          organization="${ORG}" \
          country="US" \
          max_ttl="${VAULT_CLIENT_CERT_TTL}"
fi