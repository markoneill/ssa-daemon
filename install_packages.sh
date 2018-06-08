#!/bin/bash

echo 'Installing libraries for tls_wrapper'
sudo dnf install kernel-devel libnl3-devel libevent-devel openssl-devel avahi-devel libconfig-devel gtk3-devel elfutils-libelf-devel qrencode
echo 'Installed'
