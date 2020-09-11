#ASSUMING BYTE ORDER = 'BIG'
BYTE_ORDER='big'
#import sys,getopt
import socket
import argparse
from threading import Thread
import hashlib
from hashlib import sha256
import rsa
from rsa import VerificationError
from rsa import PublicKey


def make_socket(port):
    serversocket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM) #INET Streaming Socket
    serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverip='127.0.0.1'
    serversocket.bind((serverip,port)) #gethostname makes socket visible to outside world (as opposed to just locally)
    return serversocket

def parse_data(data):
    PI = data[:4] #first 4 bytes are Unique Packet ID for the checksummed binary
    PS=data[4:8]#Packet Sequence # (Total Checksums Processed)
    XKey=data[8:10]#Multibyte Repeating XOR Key
    CS=data[10:12]# num of Checksums
    RK=data[12:len(data)-64] #Repeating key XOR'd Cyclic Checksum CRC32 DWORDs
    SIG=data[len(data)-64:] #RSA 512 SHA-256 Digital Signature
    return PI,PS,XKey,CS,RK,SIG

def verify_signature(data,signature):
    #To verify the signature, I must decrypt the signature given, and compare it to the hashed msg



    msg=data[:len(data)-64] #bytes

    pKey=get_key()
    try:
        print(f"\n\nmessage:{(msg)}\n\nsignature:{(signature)}\n\npkey:{(pKey)}\n\n")
        rsa.verify(msg,signature,pKey)
        print("No error!")
    except VerificationError:
        print ("Verification Error")

#returns key and exponent as int
def get_key(path='key.bin'): #By default path is 'key.bin'
    with open(path,'rb') as f:
        mykeybin=f.read()
    #RSA 512 has public key length of 64 bytes (512 bits)
    #These are still in byte form
    publicKey=mykeybin[3:]
    exponent=mykeybin[:3]

    rsaPubKey= PublicKey(int.from_bytes(publicKey,byteorder=BYTE_ORDER),int.from_bytes(exponent,byteorder=BYTE_ORDER))
    return rsaPubKey

def do_stuff(data,ip,port):
    #TO DO: Make sure data is at long enough to hold all required fields
    packet_id,packet_seq,XOR_Key,checksums,repeating_key,signature=parse_data(data)
    print (f'message: {len(data[:len(data)-64])}\nsignature: {len(signature)}\ndata: {len(data)}')
    verify_signature(data,signature)

if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Process some socket data.')
    #Ununused
    parser.add_argument('-d',default=180) #Delay in seconds for writing to log files
    #Used
    parser.add_argument('-p',default=1337) #Port to receive packets on
    #Unused - for signature verification
    parser.add_argument('--keys',default={"0x42": "key.bin", "0x1337": "super_secret_key.bin"}) #a dictionary of {packet_id: key_file_path} mappings
    #Unused - for checksum verification
    parser.add_argument('--binaries',default={"0x42": "cat.jpg", "0x1337": "kitten.jpg"}) #a dictionary of {packet_id: binary_path} mappings

    args=vars(parser.parse_args())
    port=args['p']


    my_sock=make_socket(port)

    while 1:
        (clientData,clientAddr)=my_sock.recvfrom(1024) #use recvfrom() instead of recv() to get client's address
        ip,port=str(clientAddr[0]),str(clientAddr[1])

        try:
            print ('\n---------------------------------------------------')
            Thread(target=do_stuff,args=(clientData,ip,port)).start()
        except KeyboardInterrupt:
            print(f"\nThread failed to start due to error\n")
            my_sock.shutdown(0)
            my_sock.close()

    my_sock.shutdown(0)
    my_sock.close()
