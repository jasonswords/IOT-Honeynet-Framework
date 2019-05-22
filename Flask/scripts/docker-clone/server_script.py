import threading
import socketserver
import time

banner = []
port_list = []
port_banner_dict = {}

"""
This function reads in two text files previously created from the bash script
and uses the information (Port, Banner) to open sockets
"""
def read_files():
    try:
        with open("ports.txt") as f:
            for l in f:
                port_list.append(int(l.strip()))
    except IOError as err:
        print('Error reading ports file')
    try:
        with open("banners.txt") as bann:
            for b in bann:
                if b in ['\n', '\r\n']:
                    banner.append('-')
                else:
                    banner.append(b.strip())
    except IOError as err:
        print('Error reading banner file')
    try:
        for i in range(0, len(port_list)):
            port_banner_dict.update({ port_list[i]:banner[i]})
    except IOError as err:
        print('Error populating dictionary')

"""
This class handles the requests from connections made
for ssh sockets, or can be implemented for any connection
that requires login
"""
class RequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
         while True:
            try:
                self.request.sendall(bytes("Please login:  \nUsername:  ", 'ascii'))
                user = str(self.request.recv(1024), 'ascii')
                self.request.sendall(bytes("Password:  ", 'ascii'))
                passwd = str(self.request.recv(1024), 'ascii')
                response = bytes("Username {}\n or Password {}\n are invalid".format(user, passwd), 'ascii')
                self.request.sendall(response)
            except (KeyboardInterrupt, BrokenPipeError, OSError) as err:
                print("Connection Ended")
                break

"""
This class handles the return of banners for any ports that do not use logins,
and return an empty string where no banner is relevant
"""
class RequestHandlerBanner(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            (host, port) = self.server.server_address #return port number
            banner = port_banner_dict.get(port) #retrieve banner relevant to port number
            if not banner: #check banner value for empty string
                banner = " "
            self.request.sendall(bytes(banner + '\n', 'ascii'))
        except (KeyboardInterrupt, BrokenPipeError, OSError) as err:
            print("Connection Ended")


"""
This class implements multi threading for each connection, and creates a separate thread for each 
socket created.
"""
class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    #This method calls the readfile function to populate all variables used.
    read_files()
    #empty host defaults to localhostla
    HOST = ''
    #initialise variables used for holding each instance
    server , server_thread = [], []
    #loop to create a separate thread for each socket
    for i in range(len(port_list)):
        #check port number for possible login needed
        if port_list[i] in {21,22}:
            #call handler to display login
            server.append(ThreadedTCPServer((HOST, port_list[i]), RequestHandler))
        else:
            #call handler to display the relevant banner message
            server.append(ThreadedTCPServer((HOST, port_list[i]), RequestHandlerBanner))
        server_thread.append(threading.Thread(target=server[i].serve_forever))
        server_thread[i].setDaemon(True)
        server_thread[i].start()
    while 1:
        time.sleep(1)
