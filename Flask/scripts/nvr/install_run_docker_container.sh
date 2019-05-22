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

sudo docker build -t nvr .

sudo docker run -p 80:80 -p 443:443 -p 554:554 -p 3800:3800 -p 5000:5000 -p 37777:37777 -p 49152:49152  nvr 