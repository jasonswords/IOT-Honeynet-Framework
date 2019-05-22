#!/usr/bin/env bash

# file path for directory structure
path=$(pwd)

# arguments passed: $1 = ssh key name
#                   $2 = instance public dns(ip)
#                   $3 = directory name for scp to move directory to instance
ssh_key=$1
aws_pub_dns=$2
clone_name=$3
aws_user="ec2-user"

dir="scripts"
ports="ports.txt"
banner="banners.txt"
ssh_dir="ssh-keys"

chmod 400 $path/ssh-keys/$ssh_key

scp -o StrictHostKeyChecking=no -i $path/$ssh_dir/$ssh_key -r $path/$dir/$clone_name $aws_user@$aws_pub_dns:~/  || sudo scp -o StrictHostKeyChecking=no -i $path/$ssh_dir/$ssh_key -r $path/$dir/$clone_name $aws_user@$aws_pub_dns:~/

ssh -o StrictHostKeyChecking=no -i $path/$ssh_dir/$ssh_key $aws_user@$aws_pub_dns 'cd $clone_name* && sudo bash install_run_docker_container.sh'

