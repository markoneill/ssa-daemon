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
	echo -e "\tbuild_daemon:\tbuild the tls_wraper"
	echo -e "\tbuild_ssa\tbuild and insert the ssa"
	echo -e "\trebuild_tests:\tclean and build each test"
	echo -e "\trebuild_daemon:\tclean and build the tls_wraper"
	echo -e "\trebuild_ssa\tclean, build and insert the ssa"
	echo -e "\trun:\t\trun all the tests without rebuilding them"
	echo -e "\tusage:\t\tprint this usage statement"
	return $?
}

function is_root {
	if [[ $EUID -ne 0 ]]; then
		echo -e "$1"
		return -1
	fi
	return 0
}

function remove_ssa_kernelmodule {
	echo "Removing ssa kernel modual"
	is_root "Options on the ssa require root privleges.\n\
		Change to root user and try again."

	if [[ $SSA_INSTALLED -gt 0 ]]; then
		rmmod ssa
		SSA_INSTALLED=`$(kmod list | grep -c ssa)`
	fi
}

function set_ssa_dir {
	if [ ! -d ${SSA_DIR} ]; then 
		SSA_DIR=${SSA_HOME}
		if [ ! -d ${SSA_DIR} ]; then
			echo -e "could not locate the SSA.\n\
				Please clone the ssa into the folder containing the ssa-daemon or\
			        specify the path to the ssa in SSA_HOME environment variable and \
			       	try again"
			 exit 1
		fi
	fi
}

function clean_ssa {
	is_root "Options on the ssa require root privleges.\n\
		Change to root user and try again."

	set_ssa_dir
	echo -e "\tcleaning project at $SSA_DIR"
	make -s -C $SSA_DIR clean
	rm $SSA_DIR/ssa.ko
}


function build_ssa {
	is_root "Options on the ssa require root privleges.\n\
		Change to root user and try again."

	cd ${SSA_DIR}
	make -s clean
	make -s || (echo -e "\tbuild failed" ; exit 1)
	cd ${HOME_DIR}
}

function insert_ssa {
	echo "Locating ssa"

	if [ $SSA_INSTALLED -eq 0 ]; then
		echo -e "\tno ssa module in kernel"
		if [ ! -f ${SSA_DIR}/$SSA_KO ]; then
			echo -e "\t$SSA_KO does not exist"
			set_ssa_dir
			build_ssa
		fi
		insmod ${SSA_DIR}/ssa.ko || exit 1
		sleep .5
		echo -e "\tssa module inserted"
	else
		echo -e "\tmodule found in kernel"
	fi
}

function init_dir {
	# Make sure we are in the right directory
	echo "checking direcotry dependencies..."
	missing=false
	if [ ! -d ${WRAPPER_DIR} ]; then
		echo -e "\terror: missing directory dependency ${WRAPPER_DIR}"
		missing=true
	fi
	if [ ! -d ${LOG_DIR} ]; then
		echo -e "\tmaking log directory"
		mkdir ${LOG_DIR} || (echo "\tfailed to make ${LOG_DIR}" && $missing=true)
		missing=true
	fi
	if [[ $missing = false ]]; then
		echo -e "\tall directorys present"
	fi
	return 0
}

function clean_daemon {
	echo "clean project ssa-daemon"
	make -s -C $WRAPPER_DIR clean
}

function build_daemon {
	echo "make project ssa-daemon"
	make -s -C ${WRAPPER_DIR} || (echo -e "\ttls_wrapper build error.\nexiting" ; exit 1)
}

function build_tests {
	make -s all
}

function run_tests {
	echo "starting tests..."
	
	let kill_daemon=false
	if [ `ps -au | grep -c tls_wrapper` -lt 1 ]; then
		is_root "tls_wrapper must be run as root.\nChange to root user and try again."

		cd ${WRAPPER_DIR}
		./tls_wrapper  1>${LOG_DIR}/tls_wrapper.log 2>&1 || echo -e "\ntls_wrapper died" &
		kill_daemon=true
	fi

	tests=($(find -maxdepth 1 -perm -111 -type f | grep -v run_tests.sh))
	for ix in "${tests[@]}"
	do
		echo -e "\n\n\t$ix\n"
		printf "%`tput cols`s\n" | tr ' ' '*'
		$ix
	done
	       	

	echo "done"
	if [ $kill_daemon = true ]; then
		pkill tls_wrapper
	fi
}


function main {
	if [ -n $1 ]; then
		MODE="$1"
		echo "mode = \"${MODE}\""
	else
		print_usage ${0}
		return 0
	fi

	init_dir

	if [[ ${MODE} = all ]]; then
		build_tests
		run_tests
		return 0
	fi
	if [[ ${MODE} = rebuild_tests ]]; then

		MODE="build_tests"
	fi
	if [[ ${MODE} = build_tests ]]; then
		build_tests
		return 0
	fi
	if [[ ${MODE} = rebuild_daemon ]]; then
		clean_daemon
		MODE="build_daemon"
	fi
	if [[ ${MODE} = build_daemon ]]; then
		build_daemon
		return 0;
	fi
	if [[ ${MODE} = rebuild_ssa ]]; then
		remove_ssa_kernelmodule
		clean_ssa
		MODE="build_ssa"
	fi
	if [[ ${MODE} = build_ssa ]]; then
		build_ssa
		return 0
	fi
	if [[ ${MODE} = run ]]; then
		run_tests
		return 0
	fi
	if [[ ${MODE} = usage ]]; then
		print_usage ${0}
		return 0
	fi

	echo "Unknown mode ${MODE}"
	print_usage ${0}
	return 0
}

main $1
