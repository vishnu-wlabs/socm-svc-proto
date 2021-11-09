FROM vault:1.8.5

ENV VAULT_ADDR http://127.0.0.1:8200/
ENV VAULT_API_ADDR http://ca-service:8200

COPY vault.hcl /vault/config/vault.hcl

ENTRYPOINT vault server -config=/vault/config/vault.hcl
