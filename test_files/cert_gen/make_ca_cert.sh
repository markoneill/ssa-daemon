#!/bin/bash

openssl req -x509 -config openssl-ca.cnf -newkey rsa:4096 -sha256 -nodes -out ca.crt -outform PEM
openssl x509 -purpose -in ca.crt -inform PEM
