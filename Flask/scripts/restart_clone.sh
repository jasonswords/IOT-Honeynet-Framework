#!/usr/bin/env bash

aws_pub_dns=$1
ssh_key=$2

path=$(pwd)


aws_user="ec2-user"
ssh_dir="ssh-keys"



id=$(sudo docker ps -aq)

sudo docker start $id



ssh -o StrictHostKeyChecking=no -i $path/$ssh_dir/$ssh_key $aws_user@$aws_pub_dns 'id=$(sudo docker ps -aq) && sudo docker start $id'
