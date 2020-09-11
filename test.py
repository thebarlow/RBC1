class key:
    name='key'
if __name__=='__main__':
    #----------------------------------------------------------
    #Testing to retrieve specific arguments
    #import argparse
    # parser=argparse.ArgumentParser()
    # parser.add_argument('-t',default=10)
    # parser.add_argument('-x',default=100)
    #
    # holder=vars(parser.parse_args())
    #
    # print(holder['t'])
    #----------------------------------------------------------
    #----------------------------------------------------------
    #How to prematurely close a socket
    # import socket
    # sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # sock.bind(  (socket.gethostname(),12345)    )
    # try:
    #     sock.recv(5)
    # except KeyboardInterrupt:
    #     print ('closing')
    #     sock.shutdown()
    #     sock.close()
    # sock.shutdown()
    # sock.close()
    #----------------------------------------------------------
    #----------------------------------------------------------
    #How to read a file in python
    # with (open('./udp_packet_challenge/cat.jpg','rb')) as f:
    #     read_file=f.read() #every read(1) is 8 bits
    #
    # print (read_file.hex())
    #----------------------------------------------------------
    #----------------------------------------------------------
    #Logging to files
    # f = open("example_test.txt", "w")
    # f.write("Now the file has more content!")
    # f.close()
    #
    # #open and read the file after the appending:
    # f = open("example_test.txt", "r")
    # print(f.read())
    #----------------------------------------------------------
    #----------------------------------------------------------
    # #Getting the public key
    # with open('./udp_packet_challenge/key.bin','rb') as f:
    #     mykeybin=f.read()
    # myKey=mykeybin
    # public=mykeybin[:64]
    # exponent=mykeybin[64:]
    # print(f'public: {int(public.hex(),16)}\nexponent: {int(exponent.hex(),16)}')
    #----------------------------------------------------------
    #----------------------------------------------------------
    #Testing signature decryption and message hashing (attempt 1 - Fail)
    #key=0x100019902c4a66b1ff76392919e7bbc35d51a5128b9da03e131b489d5ed01c1d075fc4c139a9952e9a3b040d984219a4aef0d421f6b8f9c79e1c3c35a218ecb
    #exponent=0xa54dc9
    # from hashlib import sha512
    # publicKey=0x100019902c4a66b1ff76392919e7bbc35d51a5128b9da03e131b489d5ed01c1d075fc4c139a9952e9a3b040d984219a4aef0d421f6b8f9c79e1c3c35a218ecb
    # exp=0xa54dc9
    # sig=0x1193847df2dfc0605de4f34bd0290146f3b78f83a469f42ff7bdfed541f5fc132856fe419f2b9f58f9bba63b3dd622b37c2769f5fb1811fa2ee8b0a99edbd6ef
    # mssg=b'\x00\x00\x00B\x00\x00\x00\x00\x11\xbc\x00\x1d\xc3\xd4)v\xbd\xf5\xc2\x10 2u\x85\xd2\xc0\xda]\x1b\xb8E\x0bZ\xc2\xbd\xdb\xe6\x0cU\x1f\x8e|\xd3mK\x1e`\x9bM\x9aZ0\x7f\xf5b\x1dg\xf4nm\xa0\xe7\x95\x05;\xc4,\x01N\xea\xe9b\xd3\xe3\xb4\x13\xad\xbc\xfb\x17)\xe1\xbb\xe7\x1b\xaf\x95\xc9<?\x12\\\x02Y\xd1s\xb9I\xa4\xf2\x15\x18+\x84\xf4\x0f9)\xe6\xfe^\xc3\x81\xbd;\x98 \x05\xc8\x0c\x07\xbca\x00a4\x96\xbb'
    #
    #
    # hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
    # hashFromSignature = pow(signature, exp, publicKey)
    # print(hash)
    # print(hashFromSignature)
    # print("Signature valid:", hash == hashFromSignature)
    #----------------------------------------------------------
    #----------------------------------------------------------
    #Testing signature decryption and message hashing (attempt 2 - Fail)
    import rsa
    from rsa import PublicKey
    from rsa import VerificationError

    pubKey= PublicKey(int('0x100019902c4a66b1ff76392919e7bbc35d51a5128b9da03e131b489d5ed01c1d075fc4c139a9952e9a3b040d984219a4aef0d421f6b8f9c79e1c3c35a218ecb',16),int('0xa54dc9',16))

    sig=b'\x11\x93\x84}\xf2\xdf\xc0`]\xe4\xf3K\xd0)\x01F\xf3\xb7\x8f\x83\xa4i\xf4/\xf7\xbd\xfe\xd5A\xf5\xfc\x13(V\xfeA\x9f+\x9fX\xf9\xbb\xa6;=\xd6"\xb3|\'i\xf5\xfb\x18\x11\xfa.\xe8\xb0\xa9\x9e\xdb\xd6\xef'
    mssg=b'\x00\x00\x00B\x00\x00\x00\x00\x11\xbc\x00\x1d\xc3\xd4)v\xbd\xf5\xc2\x10 2u\x85\xd2\xc0\xda]\x1b\xb8E\x0bZ\xc2\xbd\xdb\xe6\x0cU\x1f\x8e|\xd3mK\x1e`\x9bM\x9aZ0\x7f\xf5b\x1dg\xf4nm\xa0\xe7\x95\x05;\xc4,\x01N\xea\xe9b\xd3\xe3\xb4\x13\xad\xbc\xfb\x17)\xe1\xbb\xe7\x1b\xaf\x95\xc9<?\x12\\\x02Y\xd1s\xb9I\xa4\xf2\x15\x18+\x84\xf4\x0f9)\xe6\xfe^\xc3\x81\xbd;\x98 \x05\xc8\x0c\x07\xbca\x00a4\x96\xbb'

    try:
        print(f"signature using hash of type: {rsa.find_signature_hash(sig,pubKey)}")
    except VerificationError:
        print ("Verification Error on finding hash")

    try:
        print(rsa.verify(mssg,sig,pubKey))
    except:
        print("Could not verify")
    #----------------------------------------------------------
    #----------------------------------------------------------
    #Using RSA module - this works
    # import rsa
    # from rsa import VerificationError
    #
    # (pubkey, privkey) = rsa.newkeys(512)
    # message = 'Go left at the blue tree'.encode("utf-8")
    # signature = rsa.sign(message, privkey, 'SHA-256')
    #
    # print(f'message: {type(message)}\n{message}\nsignature: {type(signature)}\n{signature}\n')
    # print(f"the message is: {message}")
    # try:
    #     name=rsa.verify(message, signature, pubkey)
    #     #print(name)
    # except VerificationError:
    #     print('failed to verify')
    #----------------------------------------------------------
    #----------------------------------------------------------
