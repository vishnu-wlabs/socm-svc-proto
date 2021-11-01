#!/bin/sh

seal_status=`vault status | jq -r '.sealed'`

if [[ $seal_status == 'true' ]]; then
echo 'Vault sealed, unsealing...'
unseal_keys=`cat /mnt/secrets/unseal_keys.sec`
  for row in $(echo "${unseal_keys}" | jq -r '.[]'); do
    vault operator unseal ${row} > /dev/null
  done
vault status
fi