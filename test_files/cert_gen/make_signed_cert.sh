#!/bin/bash

openssl ca -config openssl-ca.cnf -policy signing_policy -extensions signing_req -out personal.crt -infiles client_cert.csr
