#ASSUMING BYTE ORDER = 'BIG'
BYTE_ORDER='big'
VERIFICATION_LOG = 'verification_failures.log'
CHECKSUM_LOG = 'checksum_failures.log'
#import sys,getopt
import socket
import argparse
from threading import Thread
import hashlib
from hashlib import sha256
import rsa
from rsa import VerificationError
from rsa import PublicKey
import zlib
import os
def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')
def make_socket(port):
    serversocket=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) #INET Streaming Socket
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
def log_verify_error(PID,PSN,RH,EH):
    f= open(VERIFICATION_LOG,'a')
    f.write('0x'+(PID.hex().lstrip("0"))+'\n')
    f.write(str(int.from_bytes(PSN,BYTE_ORDER))+'\n')
    f.write(str(RH)+'\n')
    f.write(str(EH)+'\n')
    #print(f'0x{(PID.hex().lstrip("0"))}\n{int.from_bytes(PSN,BYTE_ORDER)}\n{RH}\n{EH}\n\n')
def verify_signature(msg,signature):
    #To verify the signature, I must decrypt the signature given, and compare it to the hashed msg
    expectedHash=hashlib.sha256(msg).hexdigest()
    pKey=get_key()

    signAsInt=int.from_bytes(signature,BYTE_ORDER)
    receivedHash= str(hex(pow(signAsInt,pKey.e,pKey.n)))
    receivedHashFixed=str(receivedHash)[len(str(receivedHash))-64:]

    try:
        rsa.verify(msg,signature,pKey)
        return False
    except VerificationError:
        #print(f"expected hash: {expectedHash}\nreceived hash: {(receivedHashFixed)}")
        return True
def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def inverse_crc(data):
    crc = binascii.crc32(data) & maxcrc
    invcrc = maxcrc - crc
    return invcrc.to_bytes(4, 'little')

def check_crc(data):
    return binascii.crc32(data) & maxcrc == maxcrc
def log_checksum_error(PID,PSN):
    # 0x42 (Packet ID - in hex)
    # 1109 (Packet sequence number)
    # 1119 (Cyclic checksum iteration)
    # 2165e3dd (received crc32)
    # 2165e24d (expected crc32)
    # \n (trailing newline)
    pass
def verify_checksum(PID,PSN,XORK,CS,RK):
    myPID=PID.hex()
    myPSN=int(PSN.hex(),16)
    myXORK=XORK.hex()
    myCS=int(CS.hex(),16)
    myRK=RK.hex()
    #---------------------------------------------------------------------------------------------------------------------
    crc=0
    #mydata=PID+PSN+XORK+CS
    crcList=[RK[n:n+4] for n in range(0,len(RK),4)]
    crcXorList=[byte_xor(XORK*2,crc) for crc in crcList] #length 11 for test case
    receivedCRC=[crc.hex() for crc in crcXorList] #Last element is 2165e3dd, which is what the example has!!!!!!
    print(receivedCRC)
    buffersize=65536
    with open('cat.jpg','rb') as rfile:
        print(f"cat is : {os.stat('cat.jpg').st_size} long")
        bffr=rfile.read(buffersize)
        while len(bffr)>0:
            crc=zlib.crc32(bffr,crc)
            print(format(crc & 0xFFFFFFFF, '08x'))
            bffr=rfile.read(buffersize)

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
    #print(packet_id)
    #print(f'PID:{packet_id}\nPSN:{packet_seq}\nkey: {XOR_Key}\n# of checksums: {checksums}\nRK:{repeating_key}\nlength of RK: {len(repeating_key)}\n\n')
    #Below print statement is just to make sure every packet has #checksum field
    #print(f'PSN: {int(packet_seq.hex(),16)}\n# of checksums: {int(checksums.hex(),16)}\n\n')


    #if(int(packet_seq.hex(),16)==1109): #first checksum failure
        #verify_checksum(packet_id,packet_seq,XOR_Key,checksums,repeating_key)
        #mycrc32=zlib.crc32(repeating_key)
        #print(f"PID: {packet_id}\nPSN:{packet_seq}\nXorKey: {XOR_Key}\nChecksums:{checksums}\nRK: {repeating_key}")
    msg=data[:len(data)-64]
    if(verify_signature(msg,signature)):
        #If it fails to verify print our expected and received hash
        expectedHash=hashlib.sha256(msg).hexdigest()
        pKey=get_key()

        signAsInt=int.from_bytes(signature,BYTE_ORDER)
        receivedHash= str(hex(pow(signAsInt,pKey.e,pKey.n)))
        receivedHashFixed=str(receivedHash)[len(str(receivedHash))-64:]
        log_verify_error(packet_id,packet_seq,receivedHashFixed,expectedHash)

    if(int.from_bytes(packet_seq,BYTE_ORDER)==1109): #This is the first checksum failure
        verify_checksum(packet_id,packet_seq,XOR_Key,checksums,repeating_key)

    return

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

    #Remove failure logs if they already exist - start fresh!
    if os.path.exists(VERIFICATION_LOG):
      os.remove(VERIFICATION_LOG)
    if os.path.exists(CHECKSUM_LOG):
      os.remove(CHECKSUM_LOG)

    my_sock=make_socket(port)

    while 1:
        (clientData,clientAddr)=my_sock.recvfrom(1024) #use recvfrom() instead of recv() to get client's address
        ip,port=str(clientAddr[0]),str(clientAddr[1])

        try:
            #print ('\n---------------------------------------------------')
            Thread(target=do_stuff,args=(clientData,ip,port)).start()
        except KeyboardInterrupt:
            print(f"\nThread failed to start due to error\n")
            my_sock.shutdown(0)
            my_sock.close()

    my_sock.shutdown(0)
    my_sock.close()
