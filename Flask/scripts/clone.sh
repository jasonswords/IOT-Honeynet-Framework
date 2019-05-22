#!/usr/bin/env bash

 ip=$1
 clone_name=$2

# absolute file path
path=$(pwd)
# directory name
dir="scripts"
# file that is created every time a scan is run
file="scan.txt"

#output file names 
ports="ports.txt"
banners="banners.txt"
protocols="protocols.txt"

#scan ip address using nmap
#nmap -sV -p- $ip > $path/$dir/$file
#nmap -sV -T5 -p- $ip > $path/$dir/$file

# Check it the scan file was created
if [ -s $path/$dir/$file ]; then
	# #grep files for ports and banners
	cat $path/$dir/$file | grep "open" | awk -F '[/]' '{print $1}' > $path/$dir/$ports
	cat $path/$dir/$file | grep "open" | awk '{$1=$2=$3="";print $0}' | awk '{$1=$1};1' > $path/$dir/$banners
	cat $path/$dir/$file | grep "open" | awk -F '/' '{print $2}' | awk '{print $1}' > $path/$dir/$protocols
	# Check if the directory name already exists
	if [ -d $path/$dir/$clone_name ]; then
	    rm -rf $path/$dir/$clone_name;
	fi;
    mkdir $path/$dir/$clone_name;
	# create the docker file
	python3 $path/$dir/create_dockerfile_script.py $path/$dir/
	# create the install docker script
	python3 $path/$dir/create_docker_build_script.py $clone_name $path/$dir/

	# copy all the necesasary files into folder
	cp $path/$dir/$ports $path/$dir/server_script.py $path/$dir/protocols.txt $path/$dir/$clone_name
	mv $path/$dir/$banners $path/$dir/Dockerfile $path/$dir/install_run_docker_container.sh $path/$dir/$clone_name
	# rm $path/$dir/$file
else
	# Terminal message to show if the script execured successfully
    echo "   # # # #        Problem scanning device             # # # #"
fi;









