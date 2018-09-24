#! /bin/bash

# This script will build and run the programs necisery to 
# use Client Auth with Securly at the paymore.com domain.
# If a Client Auth server is curently running remotly you
# may specify the servers IP in the TESTSHOP_SERVER_IP
# environment verialble to route paymore.com to that server
# otherwise localhost will be used and a server will run
# on your machine.
# NOTE: some browsers will cash the hosts file on start up.

HOME_DIR=${PWD}
SSA_DIR=${HOME_DIR}/../ssa
WRAPPER_DIR=${HOME_DIR}
SERVER_DIR=${HOME_DIR}/test_files/webserver-event
SSL_SPLIT_DIR=${HOME_DIR}/sslsplit
LOG_DIR=${HOME_DIR}/logs

HOST_FILE=/etc/hosts
SSA_KO=ssa.ko
LOCAL_HOST="127.0.0.1"
DOMAIN_NAME="www.paymore.com paymore.com"

if [ $TESTSHOP_SERVER_IP ]; then
	SERVER_IP=$TESTSHOP_SERVER_IP
else
	SERVER_IP=$LOCAL_HOST
fi

if [ -z "$1"]; then
	MODE="default"
else
	MODE=${1}
fi
echo "build mode = $MODE"


# Check permissions
if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root" 
	exit 1
fi


# Kill left over prosesses
pkill testShopServer
pkill sslsplit
pkill tls_wrapper
sleep .3

# Make sure we are in the right directory
echo ""
echo ""
echo "checking direcotry dependencies..."
let missing=false
if [ ! -d ${WRAPPER_DIR} ]; then
	echo -e "\terror: missing directory dependency ${WRAPPER_DIR}"
	$missing=true
fi
if [ ! -d ${SERVER_DIR} ]; then
	echo -e "\terror: missing directory dependency ${SERVER_DIR} "
	$missing=true
fi
if [ ! -d ${SSL_SPLIT_DIR} ]; then
	echo -e "\terror: missing directory dependency ${SSL_SPLIT_DIR}"
	$missing=true
fi
if [ ! -d ${LOG_DIR} ]; then
	echo -e "\tmaking log directory"
	mkdir ${LOG_DIR} || (echo "\tfailed to make ${LOG_DIR}" && $missing=true)
fi
if [ ! -d ${SSA_DIR} ]; then
	echo -e "\twarning: missing ssa source at ${SSA_DIR}"
	SSA_SOURCE=false
else
	SSA_SOURCE=true
fi
if [ $missing = false ]; then
	echo -e "\tmissing critical dependency"
	exit 1
elif [ $SSA_SOURCE == false ]; then
	echo -e "\tcritical dependancys availible"
else
	echo -e "\tno missing dependancy"
fi


# If clean moad execure make clean in each directory
if [ $MODE = "clean" ]; then
	echo "clean: cleaning directories..."
	echo -e "\t$SSA_DIR"
	make -s -C $SSA_DIR clean
	rm $SSA_DIR/ssa.ko
	echo -e "\t$WRAPPER_DIR"
	make -s -C $WRAPPER_DIR clean
	echo -e "\t$SERVER_DIR"
	make -s -C $SERVER_DIR clean
fi


# See if we need to build anything
echo "checking binary dependencies..."
if [ ! -x ${WRAPPER_DIR}/tls_wrapper ]; then
	echo -e "\tmissing tls Wrapper"
	MAKE_WRAPPER=true
else
	echo -e "\ttls Wrapper exists"
	MAKE_WRAPPER=false
fi
if [ ! -x ${SERVER_DIR}/testShopServer ]; then
	echo -e "\tmissing server"
	MAKE_SERVER=true
else
	echo -e "\tserver exists"
	MAKE_SERVER=false
fi
if [ ! -x ${SSL_SPLIT_DIR}/sslsplit ]; then
	echo -e "error: missing sslsplit.\nexiting"
	exit 1
else
	echo -e "\tsslsplit exists"
fi
if [ ! -f ${SSA_DIR}/ssa.ko ]; then
	echo -e "\tmissing ssa.ko"
	MAKE_SSA_KO=true
else
	echo -e "\tssa.ko exists"
	MAKE_SSA_KO=false
fi


# Verify kernel moduel is present
echo "checking for kernel ssa support..."
let count=$(kmod list | grep -c ssa)
if [ "$MODE" = "clean" ] && [ "$count" > "0" ]; then
	if [ $SSA_SOURCE == true ]; then
		rmmod ssa
		count="0"
		echo -e "\tclean: ssa module removed"
	else
		echo -e "\tkernel modual not updated: ssa source unavalible"
	fi
fi
if [ $count == "0" ]; then
	echo -e "\tno ssa module in kernel"
	if [ $MAKE_SSA_KO == true ]; then
		echo -e "\tbuilding ssa.ko"
		cd ${SSA_DIR}
		make -s clean
		make -s || (echo -e "\tbuild failed" ; exit 1)
		cd ${HOME_DIR}
	fi
	insmod ${SSA_DIR}/ssa.ko || exit 1
	sleep .5
	echo -e "\tssa module inserted"
else
	echo -e "\tmodule found in kernel"
fi


# Build any binarys that are missing for some reason
echo "building dependencies: wrapper(${MAKE_WRAPPER}) server(${MAKE_SERVER})"
if [ ${MAKE_WRAPPER} == true ]; then
	echo -e "\ttls_wrapper..."
	make -s -C ${WRAPPER_DIR} clean
	make -s -C ${WRAPPER_DIR} clientauth || (echo -e "\ttls_wrapper build error.\nexiting" ; exit 1)
fi
if [ ${MAKE_SERVER} == true ]; then
	echo -e "\ttestShopServer..."
	make -s -C ${SERVER_DIR} clientauth || (echo -e "\tserver build error.\nexiting" ; exit 1)
fi
echo -e "\tdone"


#adding line to host file so that paymore.com gets forwarded to localhost
echo "redirecting paymore.com to ${SERVER_IP}"
let count=$(grep -c "^[0-9.]*[[:space:]]\+${DOMAIN_NAME}" ${HOST_FILE})
echo -e "\t${count} rederects for paymore.com in ${HOST_FILE}"
if [ $count = "0" ]; then
	echo -e "\tadding redirect"
	sed -i "1 i\\${SERVER_IP} ${DOMAIN_NAME}" ${HOST_FILE}
else
	let corect_ip=$(grep -c "^${SERVER_IP}[[:space:]]\+${DOMAIN_NAME}" ${HOST_FILE})
	echo -e "\tnumber to ${SERVER_IP}=${corect_ip}"
	if [ $corect_ip = "0" ]; then
		echo -e "\tupdating hostfile with new ip"
		sed -i "0,/${DOMAIN_NAME}/ d" $HOST_FILE
		sed -i "1 i\\${SERVER_IP} ${DOMAIN_NAME}" ${HOST_FILE}
	else
		echo -e "\tredirect already exists"
	fi
fi


# Begin program execution
echo "starting programs"
echo -e "\ttls_wrapper..."
cd ${WRAPPER_DIR}
./tls_wrapper  1>${LOG_DIR}/tls_wrapper.log 2>&1 || echo -e "\ntls_wrapper died" &

echo -e "\tsslsplit..."
cd ${SSL_SPLIT_DIR}
./start.sh 1>${LOG_DIR}/sslsplit.log 2>&1 || echo -e "\nsslsplit died" &
sleep .5

if [ ${SERVER_IP} == ${LOCAL_HOST} ]; then
	echo -e "\ttestShopServer..."
	cd ${SERVER_DIR}
	./testShopServer -v -p 443 1>${LOG_DIR}/server.log 2>&1 || echo -e "\ntestShopServer died" &
fi
echo "done"
