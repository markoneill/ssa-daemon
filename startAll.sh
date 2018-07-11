#! /bin/bash
HOME_DIR=${PWD}
WRAPPER_DIR=${HOME_DIR}
SERVER_DIR=${HOME_DIR}/test_files/webserver-event
SSL_SPLIT_DIR=${HOME_DIR}/sslsplit
LOG_DIR=${HOME_DIR}/logs


# Check permissions
if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root" 
	exit 1
fi


# Kill left over prosesses
pkill testShopServer
pkill sslsplit
pkill tls_wrapper

# Make sure we are in the right directory
echo "cheking direcotry depencencies"
if [ ! -d ${WRAPPER_DIR} ]; then
	echo "error: missing directory dependency ${WRAPPER_DIR}"
	exit 1
elif [ ! -d ${SERVER_DIR} ]; then
	echo "error: missing directory dependency ${SERVER_DIR} "
	exit 1
elif [ ! -d ${SSL_SPLIT_DIR} ]; then
	echo "error: missing directory dependency ${SSL_SPLIT_DIR}"
	exit 1
elif [ ! -d ${LOG_DIR} ]; then
	echo "making log directory"
	mkdir ${LOG_DIR}
fi


# See if we need to build anything
echo "cheking binary dependencies"
if [ ! -x ${WRAPPER_DIR}/tls_wrapper ]; then
	let MAKE_WRAPPER=true
else
	echo "tls Wrapper exists"
	let MAKE_WRAPPER=false
fi
if [ ! -x ${SERVER_DIR}/testShopServer ]; then
	let MAKE_SERVER=true
else
	echo "server exists"
	let MAKE_SERVER=false
fi
if [ ! -x ${SSL_SPLIT_DIR}/sslsplit ]; then
	echo "${SSL_SPLIT_DIR}/sslsplit does not exist"
	exit 1
else
	echo "sslsplit exists"
fi


# Build any binarys that are missing for some reason
echo "building dependencies: wrapper(${MAKE_WRAPPER}) server(${MAKE_SERVER})"
if [ ${MAKE_WRAPPER} = true ]; then
	echo -e "\ttls_wrapper..."
	make -s -C ${WRAPPER_DIR} clean
	make -s -C ${WRAPPER_DIR} clientauth
fi
if [ ${MAKE_SERVER} = true ]; then
	echo -e "\ttestShopServer..."
	make -s -C ${SERVER_DIR}
fi


# Begin program exicution
echo "starting programs"
echo -e "\ttls_wrapper..."
${WRAPPER_DIR}/tls_wrapper  >${LOG_DIR}/tls_wrapper.log 2>&1 &

echo -e "\tsslsplit"
cd ${SSL_SPLIT_DIR}
./start.sh 1>${LOG_DIR}/sslsplit.log 2>&1 &
cd ${HOME_DIR}
sleep .3
echo -e "\ttestShopServer"
cd ${SERVER_DIR}
./testShopServer -p 443 -v >$LOG_DIR/server.log 2>&1 &
