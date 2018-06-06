#!/bin/bash

echo 'Installing libraries for tls_wrapper'
sudo dnf install kernel-devel libnl3-devel libevent-devel openssl-devel avahi-devel libconfig-devel gtk3-devel elfutils-libelf-devel qrencode-3.4.4-5.fc28.x86_64
echo 'Installed'
