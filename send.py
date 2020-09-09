#Will send prerecorded UDP packets to 127.0.0.1 on port 1337. First packet is guaranteed to be
#correct. Packet IDs are 0x42.

import pickle
import socket
import time
import random


random.seed(0x1337)
print("Opened send.py")

with open('payload_dump.bin', 'rb') as f:
    payloads = pickle.load(f, encoding="bytes") #open file as read only binary, encode as bytes bc its reading UDP packet

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)#af_inet =communicate with ipv4 addresses, sock_dgram = udp
count = 0


#send each UDP packet to local host: 1337, wait 1 ms in between sends
for payload in payloads:
    count += 1
    print('sending payload ',payload)
    sock.sendto(payload, ('127.0.0.1', 1337))
    time.sleep(1) #change to 0.001s before submission

sock.close()
