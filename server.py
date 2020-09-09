
import sys,getopt
import socket
import argparse
from threading import Thread


def make_socket(port):
    serversocket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM) #INET Streaming Socket
    serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('socket created')
    #serverip=socket.gethostname() #supposed to make socket visible to outside world - not the same as 127.0.0.1
    serverip='127.0.0.1'
    serversocket.bind((serverip,port)) #gethostname makes socket visible to outside world (as opposed to just locally)
    print(f'bound to {serverip} : {port}')
    return serversocket

def do_stuff(data,ip,port):
    print ("doing it")

if __name__=='__main__':
    #main(sys.argv[1:])
    parser = argparse.ArgumentParser(description='Process some socket data.')
    parser.add_argument('-d',default=180) #Delay in seconds for writing to log files
    parser.add_argument('-p',default=1337) #Port to receive packets on
    parser.add_argument('--keys',default={"0x42": "key.bin", "0x1337": "super_secret_key.bin"}) #a dictionary of {packet_id: key_file_path} mappings
    parser.add_argument('--binaries',default={"0x42": "cat.jpg", "0x1337": "kitten.jpg"}) #a dictionary of {packet_id: binary_path} mappings
    #print(parser.parse_args())

    args=vars(parser.parse_args())
    port=args['p']


    my_sock=make_socket(port)
    print('socket listening')

    my_sock.recv(5) #Up to 5 unaccepted connection before refusing new ones
    print ('received some data!')
    while 1:
        (clientData,clientAddr)=my_sock.recvfrom(1024) #use recvfrom() instead of recv() to get client's address
        ip,port=str(clientAddr[0]),str(clientAddr[1])

        try:
            print ('Making new Thread')
            Thread(target=do_stuff,args=(clientData,ip,port)).start()
        except:
            print("\nThread failed to start\n")

    my_sock.shutdown()
    my_sock.close()
