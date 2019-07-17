#!/usr/bin/env bash

# Example: ./mkca.sh alpha one 3650

caAlias=$1
rootCaAlias=$2
days=$3
pswrd=123456

# Create dir
mkdir ca-$caAlias

# Create serial file
echo 1000 > ca-$caAlias/serial.txt

# Create key pair and signature request
openssl req -new -keyout ca-$caAlias/cakey.pem -out ca-$caAlias/careq.pem -config openssl.cfg

# Signature
if [ $caAlias = $rootCaAlias ]; then
	openssl x509 -signkey ca-$caAlias/cakey.pem -req -days $days -in ca-$caAlias/careq.pem -out ca-$caAlias.cer -extensions v3_ca
else 
	openssl x509 -CA ca-$rootCaAlias.cer -CAkey ca-$rootCaAlias/cakey.pem -CAserial ca-$rootCaAlias/serial.txt -req -in ca-$caAlias/careq.pem -out ca-$caAlias.cer -days $days -extensions v3_ca
fi

if [ $caAlias != $rootCaAlias ]; then
	# Check verify
	openssl verify -CAfile ca-$rootCaAlias.cer ca-$caAlias.cer
fi

# Import cert to truststore
keytool -import -alias $caAlias -file ca-$caAlias.cer -keystore truststore-$caAlias.jks -storepass $pswrd
