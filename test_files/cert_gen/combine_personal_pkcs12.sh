#!/bin/bash

openssl pkcs12 -export -out ../combined_personal.pfx -inkey personal.key -in personal.crt
