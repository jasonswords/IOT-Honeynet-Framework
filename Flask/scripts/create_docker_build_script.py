"""
This script will create the Docker build file dynamically,
formatting all ports as necessary, in order to open the
ports of the container.
"""

import sys

dockerImageName = sys.argv[1]
path = sys.argv[2]


#Adding file path to file names to store files in specific directory
file_name = path + 'install_run_docker_container.sh'
iot_dir_name="newDirectory"
file = path + "ports.txt"
# dockerImageName = 'dockerimage'



# simple function to read file of ports and format the ports
# as required by the Docker build file
def get_ports():
    ports_list =''
    try:
        with open(file) as p:
            for l in p:
                # format port mapping   port:port
                ports_list+='-p '+l.strip()+':'+l.strip()+ ' '
    except FileExistsError as e:
        print("Port list file not found")
        # Display file not found error on page
    return ports_list

# write Docker build file
try:
    with open(file_name, 'w') as d:
        d.write('#!/bin/bash\n')
        d.write('\nhaveProg() {')
        d.write('\n[ -x "$(which $1)" ]')
        d.write('\n}\n')
        d.write('\nif haveProg apt-get ; then sudo apt-get update && sudo apt-get upgrade -y && sudo apt-get install -y docker')
        d.write('\nelif haveProg yum ; then sudo yum update -y && sudo yum -y install docker')
        d.write('\nelif haveProg pacman ; then sudo pacman -Syyu && sudo pacman -S docker')
        d.write('\nelse echo "No package manager found!"')
        d.write('\nexit 2')
        d.write('\nfi\n')
        d.write('\nsudo service docker start\n')
        d.write("\nsudo docker build -t {} .\n".format(dockerImageName))
        d.write("\nsudo docker run {} {} ".format(get_ports(), dockerImageName))
except IOError as err:
    print('Error creating file')

