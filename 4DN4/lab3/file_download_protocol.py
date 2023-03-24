#!/usr/bin/env python3

########################################################################
#
# Simple File Request/Download Protocol
#
########################################################################
#
# When the client connects to the server and wants to request a file
# download, it sends the following message: 1-byte GET command + 1-byte
# filename size field + requested filename, e.g., 

# ------------------------------------------------------------------
# | 1 byte GET command  | 1 byte filename size | ... file name ... |
# ------------------------------------------------------------------

# The server checks for the GET and then transmits the requested file.
# The file transfer data from the server is prepended by an 8 byte
# file size field as follows:

# -----------------------------------
# | 8 byte file size | ... file ... |
# -----------------------------------

# The server needs to have REMOTE_FILE_NAME defined as a text file
# that the client can request. The client will store the downloaded
# file using the filename LOCAL_FILE_NAME. This is so that you can run
# a server and client from the same directory without overwriting
# files.

########################################################################

import socket
import argparse
import threading
import time
import os

########################################################################

# Define all of the packet protocol field lengths.

CMD_FIELD_LEN = 1  # 1 byte commands sent from the client.
FILENAME_SIZE_FIELD_LEN = 1  # 1 byte file name size field.
FILESIZE_FIELD_LEN = 8  # 8 byte file size field.

CMD = {"GET": b'\x01',
       "PUT": b'\x02',
       "LIST": b'\x03',
       "LLIST": b'\x04',
       "CONNECT": b'\x05',
       "BYE": b'\x06',
       "SCAN": b'\x07',
       }

CMD_CLIENT = {"GET": b'\x01',
       "PUT": b'\x02',
       "RLIST": b'\x03',
       "LLIST": b'\x04',
       "CONNECT": b'\x05',
       "BYE": b'\x06',
       "SCAN": b'\x07',
       }
MSG_ENCODING = "utf-8"
SOCKET_TIMEOUT = 100


########################################################################
# recv_bytes frontend to recv
########################################################################

# Call recv to read bytecount_target bytes from the socket. Return a
# status (True or False) and the received butes (in the former case).
def recv_bytes(sock, bytecount_target):
    # Be sure to timeout the socket if we are given the wrong
    # information.
    sock.settimeout(SOCKET_TIMEOUT)
    try:
        byte_recv_count = 0  # total received bytes
        recv_bytes = b''  # complete received message
        while byte_recv_count < bytecount_target:
            # Ask the socket for the remaining byte count.
            new_bytes = sock.recv(bytecount_target - byte_recv_count)
            # If ever the other end closes on us before we are done,
            # give up and return a False status with zero bytes.
            if not new_bytes:
                return (False, b'')
            byte_recv_count += len(new_bytes)
            recv_bytes += new_bytes
        # Turn off the socket timeout if we finish correctly.
        sock.settimeout(None)
        return (True, recv_bytes)
    # If the socket times out, something went wrong. Return a False
    # status.
    except socket.timeout:
        sock.settimeout(None)
        print("recv_bytes: Recv socket timeout!")
        return (False, b'')

########
# SDP


########################################################################
# SERVER
########################################################################

class Server:
    HOSTNAME = "0.0.0.0"

    SDP_PORT = 30000
    FSP_PORT = 30001

    BRO_ADDRESS_PORT = (HOSTNAME, SDP_PORT)

    TCP_HOSTNAME = ("127.0.0.1", FSP_PORT)

    RECV_SIZE = 1024
    BACKLOG = 20

    FILE_NOT_FOUND_MSG = "Error: Requested file is not available!"
    SERVER_DIR = os.getcwd()

    # This is the file that the client will request using a GET.
    # REMOTE_FILE_NAME = "greek.txt"
    # REMOTE_FILE_NAME = "twochars.txt"
    # REMOTE_FILE_NAME = "ocanada_greek.txt"
    # REMOTE_FILE_NAME = "ocanada_english.txt"

    def __init__(self):
        self.thread_list = []
        self.udp_get_socket()
        self.udp_receive_forever()
        self.create_file_socket()  #tcp
        self.process_connections_forever()

        # self.create_file_socket()
        # self.process_connections_forever()

    def udp_get_socket(self):
        try:
            # Create an IPv4 UDP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Bind to all interfaces and the agreed on broadcast port.
            self.socket.bind(self.BRO_ADDRESS_PORT)

            print("Listening on port {} ...".format(self.BRO_ADDRESS_PORT))

        except Exception as msg:
            print(msg)
            exit()

    def udp_receive_forever(self):
        try:
            UDP_thread = threading.Thread(target=self.udp_connection_handler, args=())

            # Record the new thread.
            self.thread_list.append(UDP_thread)

            # Start the new thread running.
            print("Starting serving thread: ", UDP_thread.name)
            UDP_thread.daemon = True
            UDP_thread.start()
        except KeyboardInterrupt:
            self.socket.close()
            exit()

    def udp_connection_handler(self):
        #print("UDP thread created!")
        while True:
            try:
                data, address = self.socket.recvfrom(self.RECV_SIZE)
                print("Broadcast received: ", data.decode('utf-8'), address)
                if (data.decode(MSG_ENCODING) == "SERVICE DISCOVERY"):
                    print("-" * 90)
                    print("Connection request recieved from {}".format(address))
                    self.socket.sendto("G28 File Sharing Service".encode(MSG_ENCODING), address)

            except socket.timeout:
                self.socket.close()
            except KeyboardInterrupt:
                print();
                exit()
            except Exception as msg:
                print(msg)
                exit()



    # Create TCP port for file sharing
    def create_file_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print("TCP Connected")

            # Set socket layer socket options.
            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind socket to socket address, i.e., IP address and port, and non blocking
            self.tcp_socket.bind(self.TCP_HOSTNAME)
            print("listening on addess",format(self.TCP_HOSTNAME))

            # Set the (listen) socket to non-blocking mode
            # self.socket.setblocking(False)
            # Set socket to listen state.
            self.tcp_socket.listen(Server.BACKLOG)
            print("Listening for file sharing connections on port {}".format(Server.FSP_PORT))

        except Exception as msg:
            print(msg)
            exit()

    def process_connections_forever(self):
        try:
            while True:
                new_client = self.tcp_socket.accept()
                print("Connection established!")
                # A new client has connected. Create a new thread and
                # have it process the client using the connection
                # handler function.
                new_thread = threading.Thread(target=self.connection_handler,
                                              args=(new_client,))

                # Record the new thread.
                self.thread_list.append(new_thread)

                # Start the new thread running.
                print("Starting serving thread: ", new_thread.name)
                new_thread.daemon = True
                new_thread.start()
        except socket.timeout:
            self.tcp_socket.close()
        except KeyboardInterrupt:
            print()
        finally:
            self.tcp_socket.close()

    def connection_handler(self, client):
        try:
            print("-" * 90)
            while True:
                connection, address = client

                print("Connection received from {}.".format(address))

                ################################################################
                # Process a connection and see if the client wants a file that
                # we have.

                # Read the command and see if it is a GET command.
                status, cmd_field = recv_bytes(connection, CMD_FIELD_LEN)

                print("Command field is:", cmd_field)

                # If the read fails, give up.
                if not status:
                    print("Closing connection ...")
                    connection.close()
                    return
                if not cmd_field:
                    print("close connection")
                    connection.close()

                # Convert the command to our native byte order.
                cmd = cmd_field
                print("Command is: ", cmd_field)

                # Case: if the input cmd is GET:
                if cmd == CMD["GET"]:
                    print("GET received.")
                    self.get(client)


                elif cmd == CMD["PUT"]:
                    print("PUT received")
                    self.put(client)

                elif cmd == CMD["LIST"]:
                    print("LIST received")
                    self.rlist(client)
                    connection.close()
                    break

                elif cmd == CMD["CONNECT"]:
                    print("CONNECT received")

                elif cmd == CMD["BYE"]:
                    print("Thank you for using the file sharing service!")
                    connection.close()
                    return

                else:
                    print("Invalid command has been input!")
                    connection.close()
                    return
            else:
                connection.close()
                self.tcp_socket.close()

        except socket.timeout:
            self.tcp_socket.close()
            connection.close()




    def rlist(self, client):

        connection, addr_port = client
        dir = self.SERVER_DIR + "/server/"

        files = os.listdir(dir)

        for file in files:
            dir = dir + file + "\t"

        msg = dir.encode(MSG_ENCODING)
        msg_len = len(msg).to_bytes(CMD_FIELD_LEN, byteorder="big")
        pkt = msg_len + msg
        connection.sendall(pkt)
        connection.close()



    def get(self, client):

        connection, addr_port = client
        status, filename_size_field = recv_bytes(connection, 1)

        filename_size = int.from_bytes(filename_size_field, byteorder='big')

        print("size is ", filename_size)

        if not status:
            print("Closing connection ...")
            connection.close()
            return

        status, filename = recv_bytes(connection, filename_size)
        print("file name is : ", filename)

        if not status:
            print("Closing connection ...")
            connection.close()
            return


        if not filename:
            print("Connection is closed!")
            connection.close()
            return

        filename = filename.decode(MSG_ENCODING)
        print("File Name: ", filename)

        print("Requesting for: ", filename)
        filename = self.SERVER_DIR + "/server/" + filename


        ################################################################
        # See if we can open the requested file. If so, send it.

        # If we can't find the requested file, shutdown the connection
        # and wait for someone else.
        try:
            file = open(filename, 'r').read()
        except FileNotFoundError:
            print(Server.FILE_NOT_FOUND_MSG)
            connection.close()
            return

        # Encode the file contents into bytes, record its size and
        # generate the file size field used for transmission.
        file_bytes = file.encode(MSG_ENCODING)
        file_size = len(file_bytes)
        file_size_byte = file_size.to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')
        print("file size byte is ", file_size_byte)



        # Create the packet to be sent with the header field.
        pkt = file_size_byte + file_bytes

        try:
            # Send the packet to the connected client.
            connection.sendall(pkt)
            print("Sending file: ", filename)
            #print("file size field: ", file_size_field.hex(), "\n")
            connection.close()
            # time.sleep(20)
        except socket.error:
            # If the client has closed the connection, close the
            # socket on this end.
            print("Closing client connection ...")
            connection.close()
            return


    def put(self, client):

        connection, address = client

        # read the filename
        print("received put command")

        status, recv_filename_size_field = recv_bytes(connection,1)

        if not status:
            print("Closing connection ...")
            connection.close()
            return

        recv_filename_size = int.from_bytes(recv_filename_size_field, byteorder='big')
        print(" received size is ", recv_filename_size)



        status, recv_filename_byte = recv_bytes(connection, recv_filename_size)

        print("recived file name is ", recv_filename_byte)

        if not status:
            print("Closing connection ...")
            connection.close()
            return

        status, recv_file_content_size = recv_bytes(connection,  1)
        recv_file_size = int.from_bytes(recv_file_content_size, byteorder='big')
        print("recived file conetent size is ", recv_file_size)


        if not status:
            print("Closing connection ...")
            connection.close()
            return

        status, recv_file_content_byte = recv_bytes(connection, recv_file_size)

        print("recived file content is ", recv_file_content_byte)

        if not status:
            print("Closing connection ...")
            connection.close()
            return

        file_recv = recv_file_content_byte.decode(MSG_ENCODING)
        file_name_recv = recv_filename_byte.decode(MSG_ENCODING)

        print("uploading file at server with name", file_name_recv)
        with open(self.SERVER_DIR + "/server/" + file_name_recv, "w") as file:
            file.write(file_recv)

        connection.close()










########################################################################
# CLIENT
########################################################################

class Client:
    RECV_SIZE = 1024
    SERVER_NAME  = "127.0.0.1"
    FSP_PORT = 30001
    # Define the local file name where the downloaded file will be
    # saved.
    DOWNLOADED_FILE_NAME = "filedownload.txt"

    cmd_field = 0

    BRO_ADDRESS_PORT = ("0.0.0.0", 30000)

    local_dir = os.getcwd()

    server_found = False

    connected  = False

    def __init__(self):

        self.scan()

        # self.create_udp_socket()
        # set the local file sharing directory to the current working directory



    def get_command(self):
        global cmd_field

        command = input("Enter command (GET/PUT/LLIST/RLIST/CONNECT/BYE/): ")

        # Create the packet cmd field.
        cmd_field = CMD_CLIENT[command]#.to_bytes(CMD_FIELD_LEN, byteorder='big')

        if (cmd_field == b'\x01'):  # GET
            filename = input("Enter filename: ")
            self.get_file(filename)

        elif (cmd_field == b'\x02'):  # PUT
            self.put()

        elif (cmd_field == b'\x04'):  # LLIST
            self.llist()

        elif (cmd_field == b'\x03'):  # RLIST
            self.rlist()

        elif (cmd_field == b'\x05' and self.server_found == True):  # CONNECT, but no current connection
            self.connect_to_server()
        elif (cmd_field == b'\x05' and self.connected == True):  # CONNECT, but current connection
            print("client already connected, try again with other command")
            self.get_command()
        elif (cmd_field == b'\x06'):  # BYE
            print("sending BYE to server")
            cmd_send = CMD["BYE"]
            self.tcp_socket.sendall(cmd_send)
            self.tcp_socket.close()

    def scan(self):
        while (self.connected == False):
            try:
                # Create an IPv4 UDP socket.
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                # Bind to all interfaces and the agreed on broadcast port.
                ##self.socket.bind(self.BRO_ADDRESS_PORT)
                print("Listening on port {} ...".format(self.BRO_ADDRESS_PORT))

                search = input("do you wanna scan for service?, enter SCAN ")
                if(search == "SCAN" and self.server_found == False):

                    # broadcasting the message
                    msg = 'SERVICE DISCOVERY'
                    self.socket.sendto(msg.encode(MSG_ENCODING), ("255.255.255.255", 30000))
                    print("Scanning...")


                    try:
                        print("Trying to connect UDP")
                        data, address = self.socket.recvfrom(self.RECV_SIZE)
                        print("Broadcast received: ", data.decode('utf-8'), address)
                        if data.decode(MSG_ENCODING) == 'G28 File Sharing Service':
                            print(f'Service found at {address[0]}, {address[1]}')
                            self.server_found = True
                            self.get_command()


                    except socket.timeout:
                        if not self.server_found:
                            print('No service found')
                        break
                    except KeyboardInterrupt:
                        print()
                        print("Closing server connection ...")
                        # If we get and error or keyboard interrupt, make sure
                        # that we close the socket.
                        self.socket.close()
                        self.tcp_socket.close()
                        self.connected = False
                        self.server_found = False
                        exit()
                    except Exception as msg:
                        print(msg)
                        exit()
                else:
                    print("not scanning")
                    exit()

            except Exception as msg:
                print(msg)
                exit()





    def connect_to_server(self):

        ip = self.SERVER_NAME
        port = self.FSP_PORT

        try:
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            exit()

        try:
            self.tcp_socket.connect((ip, port))
            print(f'Connected to server at {ip}, {port}')
            self.connected = True
            self.get_command()
        except Exception as msg:
            print(msg)
            exit()


    def llist(self):
        # list the files in the local file sharing directory
        files = os.listdir(self.local_dir)
        print('Local files:')
        for file in files:
            print(file)

        self.connected = False
        self.server_found = False

    def rlist(self):

        print("sending rlist to server")

        cmd_send = CMD["LIST"]
        try:
            self.tcp_socket.sendall(cmd_send)
        except Exception as msg:
            print(msg)
            print("please set up CONNECT before using this command")
            exit()

        # receive and output the file sharing directory listing
        data = self.tcp_socket.recv(self.RECV_SIZE).decode(MSG_ENCODING)

        print('Remote files:')
        print(data)


        self.tcp_socket.close()

        self.connected = False
        self.server_found = False

    def put(self):

        data = []

        filename = input("Enter local filename: ")

        # check if the file exists in the local file sharing directory
        filepath = os.path.join(self.local_dir, filename)

        # cannnot find
        if not os.path.isfile(filepath):
            print(f'{filename} does not exist')
            return

        print("found file local from, uploading ", filepath)

        # file exists
        with open(filename, "r") as file:
            file_content = file.read()

        cmd = CMD["PUT"]

        file_content_bytes = file_content.encode(MSG_ENCODING)
        file_size = len(file_content_bytes)
        file_size_byte = file_size.to_bytes(1, byteorder='big')

        file_name_byte = filename.encode(MSG_ENCODING)
        file_name_size = len(file_name_byte)
        file_name_size_byte = file_name_size.to_bytes(1, byteorder='big')

        print("send file with content ", file_content_bytes)
        print("send file with size ", file_size_byte)
        print("send filename with size ", file_name_size_byte)
        print("send file with cmd", cmd)

        pkt = cmd + file_name_size_byte + file_name_byte + file_size_byte + file_content_bytes

        try:
            self.tcp_socket.sendall(pkt)
        except Exception as msg:
            print(msg)
            print("please set up CONNECT before using this command")
            exit()


        file.close()

        self.tcp_socket.close()

        self.connected = False
        self.server_found = False


    def get_file(self, filename):

        ################################################################
        # Generate a file transfer request to the server
        cmd_field = CMD["GET"]

        # Create the packet filename field.
        filename_field_bytes = filename.encode(MSG_ENCODING)

        # Create the packet filename size field.
        filename_size_field = len(filename_field_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')

        # Create the packet.
        print("CMD field: ", cmd_field)
        print("Filename_size_field: ", filename_size_field)
        print("Filename field: ", filename_field_bytes)

        pkt = cmd_field + filename_size_field + filename_field_bytes

        # Send the request packet to the server.
        try:
            self.tcp_socket.sendall(pkt)
        except Exception as msg:
            print(msg)
            print("please set up CONNECT before using this command")
            exit()
        #self.tcp_socket.sendall()
        ################################################################
        # Process the file transfer repsonse from the server

        # Read the file size field returned by the server.
        status, file_size_byte = recv_bytes(self.tcp_socket, 1)


        file_size = int.from_bytes(file_size_byte, byteorder='big')

        print("received file size is ", file_size)

        if not status:
            print("Closing connection ...")
            self.tcp_socket.close()
            return

        if file_size == 0:
            self.tcp_socket.close()
            return

        # self.socket.settimeout(4)
        status, recv_file_byte = recv_bytes(self.tcp_socket, file_size)

        print("recv_file is", recv_file_byte)

        if not status:
            print("Closing connection ...")
            self.tcp_socket.close()
            return

        with open(filename, 'w') as file:
            recv_file = recv_file_byte.decode(MSG_ENCODING)
            file.write(recv_file)

        self.tcp_socket.close()
        self.connected = False
        self.server_found = False



########################################################################

if __name__ == '__main__':
    roles = {'client': Client, 'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles,
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################






