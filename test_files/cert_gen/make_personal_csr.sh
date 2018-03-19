#!/bin/bash

openssl req -config openssl-client.cnf -newkey rsa:2048 -sha256 -nodes -out client_cert.csr -outform PEM
