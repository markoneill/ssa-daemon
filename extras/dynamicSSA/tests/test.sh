#! /bin/bash

# Hacky script just to run wget and lighttpd with SSA and clean up if needed
# Run with no arguments for wget run with an argument for lighttpd
# You will need to set up the lighttpd config befor running lighttpd

if [ "$#" -ge 1 ]; then
    LD_PRELOAD=$PWD/../dynamicSSA.so ./lighttpd -D  -f /etc/lighttpd/lighttpd.conf
else
    LD_PRELOAD=$PWD/../dynamicSSA.so ./wget --ca-certificate=/etc/ssl/certs/ca-bundle.crt https://www.google.com
    #LD_PRELOAD=$PWD/dynamicSSA.so ./wget --no-check-certificate https://www.google.com

    rm index.html
fi


