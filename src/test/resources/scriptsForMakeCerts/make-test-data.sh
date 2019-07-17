#!/usr/bin/env bash

mkdir data
cp openssl.cfg data/openssl.cfg
cd data

../mkca.sh one one 3650
../mkca.sh alpha one 3650
../mkca.sh delta one 3650

keytool -import -alias alpha -file ca-alpha.cer -keystore truststore-one.jks -storepass 123456
keytool -import -alias delta -file ca-delta.cer -keystore truststore-one.jks -storepass 123456

mv truststore-one.jks truststore-all.jks

keytool -import -alias one -file ca-one.cer -keystore truststore-alpha.jks -storepass 123456
keytool -import -alias one -file ca-one.cer -keystore truststore-delta.jks -storepass 123456

../mkcert.sh login1Alpha 3650 'CN=login1Alpha, OU=Test, O=Test organization, C=RU' alpha one
../mkcert.sh login1Delta 3650 'CN=login1Delta, OU=Test, O=Test organization, C=RU' delta one

rm openssl.cfg
