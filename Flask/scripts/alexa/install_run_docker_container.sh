#!/bin/bash

haveProg() {
[ -x "$(which $1)" ]
}

if haveProg apt-get ; then sudo apt-get update && sudo apt-get upgrade -y && sudo apt-get install -y docker
elif haveProg yum ; then sudo yum update -y && sudo yum -y install docker
elif haveProg pacman ; then sudo pacman -Syyu && sudo pacman -S docker
else echo "No package manager found!"
exit 2
fi

sudo service docker start

sudo docker build -t alexa .

sudo docker run -p 4071:4071 -p 55442:55442 -p 55443:55443  alexa 