#!/bin/bash

echo "Generating new RSA keys for a node with 100 years expiry date for tests"
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <nodeId>"
    exit 1
fi

NODE_ID=$1
NODE_NAME="node$(($NODE_ID + 1))"

PUBLIC_NAME="s-public-$NODE_NAME"
PRIVATE_NAME="s-private-$NODE_NAME"

openssl genrsa -out $PRIVATE_NAME.key 3072
openssl req -new -x509 -days 36500 -key $PRIVATE_NAME.key -out $PUBLIC_NAME.pem
# NOTE: the pkcs8 -topk8 -traditional cannot be loaded by EnhancedKeyStoreLoader/Bouncy Castle. So we do rsa instead:
#openssl pkcs8 -passout pass:password -in $PRIVATE_NAME.key -out $PRIVATE_NAME.pem -topk8 -traditional
openssl rsa -in $PRIVATE_NAME.key -out $PRIVATE_NAME.pem -outform PEM
