#! /bin/bash

# This run_tests.sh script will build and run the programs from this test suit
# as well as providing a handle for rebuilding the ssa's kernel module and demon

HOME_DIR=${PWD}
LOG_DIR=${PWD}/logs
WRAPPER_DIR=${PWD%*/test_files*}
SSA_DIR=${PWD%*-daemon*}
SSA_KO=ssa.ko

SSA_INSTALLED=$(kmod list | grep -c ssa)

function print_usage {
	echo "USAGE: ${0} <mode>"
	echo -e "\twhere <mode> is one of"
	echo -e "\tall:\t\tbuild and run all tests"
	echo -e "\tbuild_test:\tbuild each test"
	echo -e "\tbuild_daemon:\tbuild the tls_wrapper"
	echo -e "\tbuild_ssa\tbuild and insert the ssa"
	echo -e "\trebuild_tests:\tclean and build each test"
	echo -e "\trebuild_daemon:\tclean and build the tls_wrapper"
	echo -e "\trebuild_ssa\tclean, build and insert the ssa"
	echo -e "\trun:\t\trun all executable files in this directory"
	echo -e "\t\t\tNOAT: if tls_wrapper is running, all tests will be executed against that instance of the daemon. Otherwise a new instance is created for each test"
	echo -e "\tusage:\t\tprint this usage statement"
	return $?
}

function require_root {
	if [[ $EUID -ne 0 ]]; then
		echo -e "$1"
		exit 1
	fi
	return 0
}

function dir_chk_logdir {
	echo "checking for log directory..."
	if [ ! -d ${LOG_DIR} ]; then
		echo -e "\tdirectory absent\n\tmaking log directory"
		mkdir ${LOG_DIR} || \
		       (echo "\tfailed to make ${LOG_DIR}" ; return 1)
	fi
	return 0
}

function dir_chk_daemon {
	if [ ! -d ${WRAPPER_DIR} ]; then
		echo -e "\terror: missing directory dependency ${WRAPPER_DIR}"
		return 1
	fi
	return 0
}

function dir_chk_ssa {
	if [ ! -d ${SSA_DIR} ]; then 
		SSA_DIR=${SSA_HOME}
		if [ ! -d ${SSA_DIR} ]; then
			echo -e "could not locate the SSA.\n\
				Please clone the ssa into the folder containing the ssa-daemon or\
			        specify the path to the ssa in SSA_HOME environment variable and \
			       	try again"
			 return 1
		fi
	fi
	return 0
}

function remove_ssa_kernel_module {
	require_root "Options on the ssa require root privileges.\n\
		Change to root user and try again."

	if [[ $SSA_INSTALLED -gt 0 ]]; then
		rmmod ssa || exit 1
		SSA_INSTALLED=$(kmod list | grep -c ssa)
	fi
	return 0
}

function clean_ssa {
	require_root "Options on the ssa require root privileges.\n\
		Change to root user and try again."
	dir_chk_ssa && \
		rm $SSA_DIR/ssa.ko && \
		make -s -C $SSA_DIR clean
	return $?
}

function build_ssa {
	require_root "Options on the ssa require root privileges.\n\
		Change to root user and try again."
	cd ${SSA_DIR}
	clean_ssa && \
		make -s || \
		(echo -e "\tbuild failed" ; exit 1)
	cd ${HOME_DIR}
	return 0
}

function insert_ssa {
	echo "Locating ssa"
	if [ $SSA_INSTALLED -eq 0 ]; then
		echo -e "\tno ssa module in kernel"
		if [ ! -f ${SSA_DIR}/$SSA_KO ]; then
			echo -e "\t$SSA_KO does not exist"
			dir_chk_ssa
			build_ssa
		fi
		insmod ${SSA_DIR}/ssa.ko || exit 1
		sleep .5
		echo -e "\tssa module inserted"
	else
		echo -e "\tmodule found in kernel"
	fi
	return 0;
}

function clean_daemon {
	echo "clean project ssa-daemon"
	dir_chk_daemon || exit 1
	make -s -C $WRAPPER_DIR clean
	return $?
}

function build_daemon {
	echo "make project ssa-daemon"
	dir_chk_daemon || exit 1
	make -s -C ${WRAPPER_DIR} || (echo -e "\terror building tls_wrapper.\nexiting" ; exit 1)
	return $?
}

function clean_tests {
	make -s clean
	return $?
}

function build_tests {
	make -s all
	return $?
}

function run_tests {
	init_dir
	echo "starting tests..."
	
	own_daemon=false
	if [ `ps -au | grep -c tls_wrapper` -lt 1 ]; then
		require_root "tls_wrapper must be run as root.\nstart the tls_wrapper or try again as root"
		echo "`date`" > ${LOG_DIR}/tls_wrapper.log
		cd ${WRAPPER_DIR}
		own_daemon=true
	fi

	tests=($(find -maxdepth 1 -perm -111 -type f | grep -v run_tests.sh))
	for ix in "${tests[@]}"
	do
		if [ $own_daemon = true ]; then
			pkill tls_wrapper
			./tls_wrapper  1>>${LOG_DIR}/tls_wrapper.log 2>&1 || \
			       	echo -e "\ntls_wrapper died" &
		fi
		echo -e "\n\n\t$ix\n"
		printf "%`tput cols`s\n" | tr ' ' '*'
		$ix
	done
	       	

	echo "done"
	if [ $own_daemon = true ]; then
		pkill tls_wrapper
	fi
}


function main {
	if [ -n $1 ]; then
		MODE="$1"
		echo "mode = \"${MODE}\""
	else
		print_usage ${0}
		return $?
	fi

	if [[ ${MODE} = "all" ]]; then
		build_tests && \
		run_tests
		return $?
	fi
	if [[ ${MODE} = "rebuild_tests" ]]; then
		clean_tests && \
			MODE="build_tests" || \
			return 1
	fi
	if [[ ${MODE} = build_tests ]]; then
		build_tests
		return $?
	fi
	if [[ ${MODE} = rebuild_daemon ]]; then
		clean_daemon && \
		       MODE="build_daemon" || \
		       return 1
	fi
	if [[ ${MODE} = build_daemon ]]; then
		build_daemon
		return $?;
	fi
	if [[ ${MODE} = rebuild_ssa ]]; then
		remove_ssa_kernel_module && \
			clean_ssa && \
			MODE="build_ssa" || \
			return 1
	fi
	if [[ ${MODE} = build_ssa ]]; then
		insert_ssa
		return $?
	fi
	if [[ ${MODE} = run ]]; then
		run_tests
		return $?
	fi
	if [[ ${MODE} = usage ]]; then
		print_usage ${0}
		return $?
	fi

	echo "Unknown mode ${MODE}"
	print_usage ${0}
	return $?
}

main $1
