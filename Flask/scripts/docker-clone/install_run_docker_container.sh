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

sudo docker build -t docker-clone .

sudo docker run -p 5000:5000 -p 5433:5433 -p 6463:6463 -p 6942:6942 -p 8000:8000 -p 8065:8065 -p 8089:8089 -p 8191:8191 -p 8999:8999 -p 30666:30666 -p 45112:45112 -p 61355:61355 -p 63342:63342  docker-clone 