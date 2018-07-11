#! /bin/bash
HOME_DIR=${PWD}
SSA_DIR=${HOME_DIR}/../ssa
WRAPPER_DIR=${HOME_DIR}
SERVER_DIR=${HOME_DIR}/test_files/webserver-event
SSL_SPLIT_DIR=${HOME_DIR}/sslsplit
LOG_DIR=${HOME_DIR}/logs

HOST_FILE=/etc/hosts
SSA_KO=ssa.ko
DOMAIN_NAME="127.0.0.1	www.testshop.com testshop.com"


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
fi
if [ ! -d ${SERVER_DIR} ]; then
	echo "error: missing directory dependency ${SERVER_DIR} "
	exit 1
fi
if [ ! -d ${SSL_SPLIT_DIR} ]; then
	echo "error: missing directory dependency ${SSL_SPLIT_DIR}"
	exit 1
fi
if [ ! -d ${LOG_DIR} ]; then
	echo "making log directory"
	mkdir ${LOG_DIR}
fi
if [ ! -d ${SSA_DIR} ]; then
	echo "warning: missing ssa source at ${SSA_DIR}"
	let SSA_SOURCE=false
else
	let SSA_SOURCE=true
fi


# See if we need to build anything
echo "cheking binary dependencies"
if [ ! -x ${WRAPPER_DIR}/tls_wrapper ]; then
	let MAKE_WRAPPER=true
else
	echo -e "\ttls Wrapper exists"
	let MAKE_WRAPPER=false
fi
if [ ! -x ${SERVER_DIR}/testShopServer ]; then
	let MAKE_SERVER=true
else
	echo -e "\tserver exists"
	let MAKE_SERVER=false
fi
if [ ! -x ${SSL_SPLIT_DIR}/sslsplit ]; then
	echo "${SSL_SPLIT_DIR}/sslsplit does not exist"
	exit 1
else
	echo -e "\tsslsplit exists"
fi
if [ ! -f ${SSA_DIR}/ssa.ko ]; then
	let MAKE_SSA_KO=true
else
	echo -e "\tssa.ko exists"
	let MAKE_SSA_KO=false
fi


# Verify kernel moduel is present
echo "cheking for kernel ssa suport..."
let count=$(kmod list | grep -c ssa)
echo -e "count = $count"
if [ $count = "0" ]; then
	echo -e "\tssa modual not found" 
	if [ MAKE_SSA_KO ]; then
		if [ ! SSA_SOURCE ]; then
			echo -e "\tno ssa source or binary. exiting"
			exit 1
		fi
		make -s -C ${SSA_DIR}
	fi
	insmod ${SSA_DIR}/ssa.ko
	echo -e "\tssa modual inserted"
else
	echo -e "\tmodual found in kernel"
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

#adding line to host file so that testshop.com gets forwarded to localhost
let count=$(grep -c "${DOMAIN_NAME}" $HOST_FILE)
if [ $count = '0' ]
then
	echo "setting hostfile to redirect testshop.com"
	sed -i "1 i\\${DOMAIN_NAME}" $HOST_FILE
else
	echo "hosts file has testshop redirect already"
fi


# Begin program execution
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
