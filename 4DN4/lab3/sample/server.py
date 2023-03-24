import socket
import argparse
import sys
import csv
from cryptography.fernet import Fernet

command_list = ["GL1A", "GL2A", "GL3A", "GL4A", "GMA", "GEA"]


class Server():

    HOSTNAME = "0.0.0.0"

    PORT = 50000

    RECV_BUFFER_SIZE = 1024
    MAX_CONNECTION_BACKLOG = 10

    MSG_ENCODING = "utf-8"

    SOCKET_ADDRESS = (HOSTNAME, PORT)

    def __init__(self):
        self.create_listen_socket()
        self.process_connections_forever()

    def create_listen_socket(self):
        try:

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            self.socket.bind(Server.SOCKET_ADDRESS)

            self.socket.listen(Server.MAX_CONNECTION_BACKLOG)
            print("Listening on port {} ...".format(Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        try:
            while True:
                self.connection_handler(self.socket.accept())
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)


    def connection_handler(self, client):


        connection, address_port = client
        print("-" * 72)
        print("Connection received from {}.".format(address_port))
        error_flag = 0
        while True:
            try:

                recvd_bytes = connection.recv(Server.RECV_BUFFER_SIZE)

                if len(recvd_bytes) == 0:
                    print("Closing client connection ... ")
                    connection.close()
                    break


                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)

                print("Received: ", recvd_str)

                student_id = str(recvd_str[:7])

                print("student requst is \n", student_id);
                print("len of id is  \n ", len(student_id))
                command = str(recvd_str[7:])

                print("option received is \n ", command)

                print("len of comman is  \n ", len(command))

                #searching the student in csv file
                student_found = 0;

                if command == 'GMA':
                    print('This is case GMA')
                elif command == 'GL1A':
                    print('This is case GL1A')
                elif command == 'GL2A':
                    print('This is case GL2A')
                elif command == 'GL3A':
                    print('This is case GL3A')
                elif command == 'GL4A':
                    print('This is case GL4A')
                elif command == 'GEA':
                    print('This is case GEA')
                elif command == 'GG':
                    print('This is case GG')
                elif command == 'GMA':
                    print('This is case GMA')
                elif command == 'GEA':
                    print('This is case GEA')
                else:
                    print('Invalid case')



                with open('course_grades_2023.csv', newline='') as csvfile:
                    l1 = []
                    l2 = []
                    l3 = []
                    l4 = []
                    mid = []
                    exam1 = []
                    exam2 = []
                    exam3 = []
                    exam4 = []

                    result_grade = ""  # Store either the student grades or the average grades strings
                    key = ""
                    encode_key = ""
                    message = ""
                    grades_file = csv.reader(csvfile)
                    for row in grades_file:
                        if (row[0] != "Name"):

                            # Requesting for student grades
                            if (command == "GG"):

                                if (str(student_id) == str(row[1])):
                                    print("user found")

                                    student_found = 1;
                                    key = row[2]
                                    # Concatenate student grade strings
                                    for i in range(3, len(row)):
                                        result_grade = result_grade + str(row[i]) + "\t"

                            elif (findCommand(command) >= 0):

                                if (str(student_id) == str(row[1])):
                                    print("user found")
                                    student_found = 1;
                                    key = row[2]


                                l1.append(int(row[3]))
                                l2.append(int(row[4]))
                                l3.append(int(row[5]))
                                l4.append(int(row[6]))
                                mid.append(int(row[7]))
                                exam1.append(int(row[8]))
                                exam2.append(int(row[9]))
                                exam3.append(int(row[10]))
                                exam4.append(int(row[11]))

                                l1Avg = str(findAverage(l1))
                                l2Avg = str(findAverage(l2))
                                l3Avg = str(findAverage(l3))
                                l4Avg = str(findAverage(l4))
                                midAvg = str(findAverage(mid))
                                exam1Avg = findAverage(exam1)
                                exam2Avg = findAverage(exam2)
                                exam3Avg = findAverage(exam3)
                                exam4Avg = findAverage(exam4)
                                examAvg = (exam1Avg + exam2Avg + exam3Avg + exam4Avg) / 4
                                examAvg = str(examAvg)

                                average_array = [l1Avg, l2Avg, l3Avg, l4Avg, midAvg, examAvg]
                                result_grade = average_array[findCommand(command)]

                            else:
                                print("Command Error!")


                    if (student_found == 0):
                        print("student not found")
                        connection.close()
                        print("avg grade",result_grade)



                    result_grade = result_grade.encode('utf-8')

                    #need to retreive from csv

                    print("key = ", key)



                    # Previously generated using: encryption_key = Fernet.generate_key()
                    # Shared by the server and client.

                    encryption_key_bytes = key.encode('utf-8')
                    # Encrypt the message for transmission at the server.
                    fernet = Fernet(encryption_key_bytes)
                    encrypted_message_bytes = fernet.encrypt(result_grade)

                    print("\nencrypted_message_bytes = ", encrypted_message_bytes)

                    message = encrypted_message_bytes + encryption_key_bytes

                    connection.sendall(message)

                    print("message sent")



            except KeyboardInterrupt:
                print()
                print("Closing client connection ... ")
                connection.close()
                break

class Client():
    SERVER_HOSTNAME = '127.0.0.1'

    RECV_BUFFER_SIZE = 1024  # Used for recv.


    def __init__(self):

        self.get_socket()
        self.connect_to_server()
        self.get_console_input()
        self.send_console_input_forever()



    def get_socket(self):
        try:

            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connect_to_server(self):
        try:
            # Connect to the server using its socket address tuple.
            self.socket.connect((Client.SERVER_HOSTNAME, Server.PORT))
            print("Connected to \"{}\" on port {}".format(Client.SERVER_HOSTNAME, Server.PORT))

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_console_input(self):
        # In this version we keep prompting the user until a non-blank
        # line is entered, i.e., ignore blank lines.
        while True:
            self.input_text = input("enter student id and command without space: ")
            print("user input is ", self.input_text)
            if self.input_text != "":
                break

    def send_console_input_forever(self):
        while True:
            try:
                self.get_console_input()
                self.connection_send()
                self.connection_receive()
            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                # If we get and error or keyboard interrupt, make sure
                # that we close the socket.
                self.socket.close()
                sys.exit(1)

    def connection_send(self):
        try:
            # Send string objects over the connection. The string must
            # be encoded into bytes objects first.

            self.socket.sendall(self.input_text.encode(Server.MSG_ENCODING))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_receive(self):

        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.

            recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)
            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end. In that case, close the connection on this
            # end and exit.
            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)

            # Previously generated using: encryption_key = Fernet.generate_key()
            # Shared by the server and client.


            #encryption_key = "PWMKkdXW4VJ3pXBpr9UwjefmlIxYwPzk11Aw9TQ2wZQ="
            result_grade = recvd_bytes[:len(recvd_bytes) - 44]
            #print("result grade = ", result_grade)
            key = recvd_bytes[len(recvd_bytes) - 44: len(recvd_bytes)]
            #print("key = ", key)




            encryption_key_bytes = key


            fernet = Fernet(encryption_key_bytes)

            decrypted_message_bytes = fernet.decrypt(result_grade)

            decrypted_message = decrypted_message_bytes.decode('utf-8')

            print("decrypted_message = ", decrypted_message)

        except Exception as msg:
            print(msg)
            sys.exit(1)


def findAverage(gradelist):
    return sum(gradelist) / len(gradelist)

def findCommand(inputCommand):
    for i in range(0, len(command_list)):
        if (inputCommand == command_list[i]):
            return i
    return -1



if __name__ == '__main__':

    roles = {'client': Client, 'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles,
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()