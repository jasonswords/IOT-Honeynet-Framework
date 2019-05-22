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

sudo docker build -t hp_printer .

sudo docker run -p 80:80 -p 139:139 -p 445:445 -p 631:631 -p 3910:3910 -p 6839:6839 -p 7435:7435 -p 8080:8080 -p 9100:9100 -p 9101:9101 -p 9102:9102 -p 9110:9110 -p 9111:9111 -p 9112:9112 -p 9220:9220 -p 9290:9290 -p 9500:9500  hp_printer 