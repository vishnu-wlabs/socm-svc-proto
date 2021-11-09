#!/bin/sh

while :
do
	http_stat=`curl -k -s -o /tmp/http_stat.out -w "%{http_code}" $VAULT_ADDR/v1/sys/seal-status`
  if [[ $http_stat == '200' ]]; then
    echo 'Vault is running. Checking if initialized...'
    is_initilized=`cat /tmp/http_stat.out|jq ".initialized"`
    if [[ $is_initilized == 'true' ]]; then
      echo  'Vault is already initialized.'
      echo 'Unseal vault using unseal keys'
      /bin/sh -c /usr/local/bin/unseal.sh
      ## Run the CA initialization script
      /bin/sh -c /usr/local/bin/setup-ca.sh
      exit
    else
      echo  'Starting Initialization.'
      echo "{\"secret_shares\": $VAULT_SECRETS_S,\"secret_threshold\": $VAULT_SECRETS_T, \
            \"recovery_shares\": $VAULT_RECOVERY_S, \"recovery_threshold\": $VAULT_RECOVERY_T }"  \
            > /tmp/http_init_post.json
      http_init=`curl -k -s -w '%{http_code}' --location --request PUT -o /tmp/http_init.out  \
                $VAULT_ADDR/v1/sys/init --header 'Content-Type: application/json' -d  @/tmp/http_init_post.json`
      echo $http_init         
      if [[ $http_init == '200' ]]; then
        root_token=`cat /tmp/http_init.out | jq -r ".root_token"`
        unseal_keys=`cat /tmp/http_init.out | jq -r ".keys_base64"| sed 's/"/\\"/g'`
        echo 'Store super secret keys in Docker Secrets (Not Production Safe)'
        echo $root_token > /mnt/secrets/root_token.sec
        echo $unseal_keys > /mnt/secrets/unseal_keys.sec

        echo 'Unseal vault using unseal keys'
        /bin/sh -c /usr/local/bin/unseal.sh
        /bin/sh -c /usr/local/bin/setup-ca.sh

        echo 'Completed Initialization.'
        echo 'Destroying stored files'
        rm -rf /tmp/http*
      else
        echo  'Failed Initialization. Try manually'
      fi
      exit
    fi
  else
    echo 'Vault is not running. Trying again'
  fi
	sleep 5
done


