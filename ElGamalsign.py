import Crypto.Util.number as num
import random
import hashlib
import argparse


def keyGen():
   
    while True:
        p = num.getPrime(256)
        q = (p-1)//2          # check for safe prime
        if(num.isPrime(q)):
            break

    while True:
        g = random.randint( 1, p-1 )
        if (pow( g, (p-1)//2, p ) != 1):
            break
    
    x = random.randint(1, p-1)
    y = pow(g, x, p)
    public_key = str(p) + "," + str(g) + "," + str(y)
    private_key = str(x)

    file = open("keyfile.txt", "w")  # store keys in file
    file.write(public_key)
    file.write("\n")
    file.write(private_key)
    file.close()

def sign(file_name: str):
    f = open(file_name, "r")
    m = f.readline()
    f.close()

    keys_text = open("keyfile.txt") 
    keys = keys_text.readlines()
    keys_text.close()

    public_key = keys[0].split(",")
    p = int(public_key[0])
    g = int(public_key[1])
    y = int(public_key[2])
    x = int(keys[1])
    
    while True:
        k = random.randint(1, p-2)
        if num.GCD(k, p-1) == 1: 
            break
    
    r = pow(g, k, p)
    hashval = hashlib.sha1(m.encode())  # hash message using sha-1
    hash_toint = int(hashval.hexdigest(), 16)  #convert hash values to int


    mod_inverse = pow(k, -1, p-1)   # calculate mod inverse
    s = (mod_inverse * (hash_toint - (x * r))) % (p-1)

    signature = str(r) + "," + str(s)
    file = open("sign.txt", "w")
    file.write(signature)
    file.close()

def verify(stext: str, original_text: str):
    keys_text = open("keyfile.txt") 
    keys = keys_text.readlines()
    keys_text.close()

    public_key = keys[0].split(",")
    p = int(public_key[0])
    g = int(public_key[1])
    y = int(public_key[2])
    x = int(keys[1])

    sign_text = open(stext, "r") 
    signs = sign_text.readline()
    sign_text.close()

    signature = signs.split(",")
    r = int(signature[0])
    s = int(signature[1])

    f = open(original_text, "r")
    m = f.readline()
    f.close()

    hash_m = int(hashlib.sha1(m.encode()).hexdigest(), 16)
    left = pow(g, hash_m, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p

    if 1 <= r <= p-1 and left == right:
        print("Verified!")
    else:
        print("Invalid signature!")
    

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-keygen', action='store_true')
    parser.add_argument('-sign', action='store_true')
    parser.add_argument('-verify', action='store_true')
    parser.add_argument('-f', type=str)
    parser.add_argument('-s', type=str)
    args = parser.parse_args()

    if args.keygen:
        keyGen()

    elif args.sign:
        sign(args.f)

    elif args.verify:
        verify(args.s, args.f)


main()

