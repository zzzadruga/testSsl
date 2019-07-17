#!/usr/bin/env bash

# Example: ./mkcert.sh login1 3650 'dname' intermediate one

alias=$1
days=$2
dname=$3
caAlias=$4
rootCaAlias=$5
pswrd=123456

# Create certificate
keytool -genkey -alias $alias -storepass $pswrd -keystore $alias.jks -keyalg RSA -keysize 2048 -validity $days -dname "$dname" -keypass $pswrd

# Create signature requst
keytool -certreq -alias $alias -storepass $pswrd -keystore $alias.jks -file $alias.csr -keypass $pswrd

# Signature:
openssl x509 -CA ca-$caAlias.cer -CAkey ca-$caAlias/cakey.pem -CAserial ca-$caAlias/serial.txt -req -in $alias.csr -out $alias.cer -days $days

# Remove request
rm -rf  $alias.csr

# Import root CA
keytool -import -trustcacerts -alias $rootCaAlias -keystore $alias.jks -file ca-$rootCaAlias.cer -storepass $pswrd

if [ $caAlias != $rootCaAlias ]; then
	# Import intermediate CA
	keytool -import -trustcacerts -alias $caAlias -keystore $alias.jks -file ca-$caAlias.cer -storepass $pswrd
fi

# Import cert
keytool -import -alias $alias -file $alias.cer -keystore $alias.jks -storepass $pswrd

# Remove CAs
keytool -keystore $alias.jks -alias $caAlias -delete -storepass $pswrd

if [ $caAlias != $rootCaAlias ]; then
	keytool -keystore $alias.jks -alias $rootCaAlias -delete -storepass $pswrd
fi
