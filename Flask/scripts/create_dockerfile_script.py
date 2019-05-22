"""
This script checks if dockerfile file exists,
if it does not exist, open the ports.txt file,
read contents of file in and format into a string called portList.
Create the dockerfile and input the portList after the EXPOSE command.
"""
import sys

path = sys.argv[1]

#Adding file path to file names to store files in specific directory
file = path + 'Dockerfile'
port_list_file = path + '/ports.txt'
server_script = 'server_script.py'

# function to create a dockerfile

def create_dockerfile(portList):
    with open(file, "w+") as d:
        d.write('FROM python:3.7')
        d.write('\nMAINTAINER R-J-T')
        d.write("\nWORKDIR /app")
        d.write("\nCOPY . /app")
        d.write("\nEXPOSE {}".format(portList))
        d.write('\nCMD ["python3", "' + server_script + '" ]')

# read file of port numbers and format into string
def read_file():
     portList = ''
     with open(port_list_file) as p:
        for l in p:
            portList+=l.strip()+ ' '
     return portList

"""
Read port list file, pass return string to the 
create dockerfile function.
"""
try:
    create_dockerfile(read_file())
except (FileExistsError, FileNotFoundError) as e:
    print("Error... Port list file not found")
    # display suitable message on website


