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


     #Create Authentication
     vault auth enable jwt

     vault write auth/jwt/config \
          oidc_discovery_url="${AZURE_OIDC_DISCOVERY_URL}" \
          bound_issuer="${AZURE_OIDC_ISSUER}" \
          default_role="jwt_client_cert"

     vault write auth/jwt/role/jwt_client_cert \
          role_type="jwt" \
          policies=flask_app_cert_gen_pol \
          bound_audiences="${AZURE_APPID}" \
          user_claim="unique_name" \
          token_no_default_policy=true \
          clock_skew_leeway=0 \
          token_num_uses=1 \
          token_type="service"


     #Create policies     
     echo 'path "pki_int/issue/client_certs" {
          capabilities = ["update"]
     }' | vault policy write flask_app_cert_gen_pol -


     


fi