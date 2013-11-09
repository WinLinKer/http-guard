#!/bin/bash
ips="192.168.0.1 192.168.0.2 192.168.0.3"
action=$1

if [ "$action" == "" ]; then
	echo "action not found"
	exit 1
fi

if [ "$action" == "get" ];then
	if [ $# -eq 2 ];then
		key=$2
		for ip in $ips
		do
			result=$(curl -s "${ip}/dict/?action=${action}&key=$key")
			echo "$ip:$result"
		done	
	else	
		echo "args numbers not right."
		exit 1
	fi	

elif [ "$action" == "set" ];then
	if [ $# -eq 3 ];then
		key=$2
		value=$3
		for ip in $ips
		do
			result=$(curl "${ip}/dict/?action=${action}&key=$key&value=$value")
			echo "$ip:$result"
		done		
	elif [ $# -eq 4 ];then
		key=$2
		value=$3
		exp=$4
		for ip in $ips
		do
			result=$(curl "${ip}/dict/?action=${action}&key=$key&value=$value&exp=$exp")
			echo "$ip:$result"
		done		
	else
		echo "args numbers not right."
		exit 1
	fi	
else
	echo "action invalid."
	exit 1
fi	
