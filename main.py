# -*- coding: utf-8 -*-
from new_sha import *
import rsa


def str_to_int(s):
    return int(bytes(s).encode('hex'), 16)


def int_to_str(num):
    res = []
    while num:
        res.append(chr(num & 0xff))
        num >>= 8
    return ''.join(reversed(res))


def gen_keys():
    pub_key, priv_key = rsa.newkeys(2048)
    a = pub_key.save_pkcs1()
    b = priv_key.save_pkcs1()
    f = open('public.key','w')
    f.write(a)
    f.close()
    f = open('private.key','w')
    f.write(b)
    f.close()


def get_keys():
    with open('private.key') as privatefile:
        keydata = privatefile.read()
        priv = rsa.PrivateKey.load_pkcs1(keydata,'PEM')
    with open('public.key') as publicfile:
        keydata = publicfile.read()
        pub = rsa.PublicKey.load_pkcs1(keydata,'PEM')
    return pub, priv


def printbin(st):
    print ''.join(format(ord(x), 'b') for x in st)


def sig_check(fname, key):
    with open(fname,'rb') as f:
        data = f.read()
        digest = sha100500(data)
        with open(fname+'.sgn', 'rb') as fsign:
            s = long(fsign.read())
            H = pow(s, key.e, key.n)
            H = int_to_str(H)
        if digest == H:
            return True
        else:
            return False


def sig_create(fname, key):
    with open(fname, 'rb') as f:
        data = f.read()
        digest = sha100500(data)
        s = pow(str_to_int(digest), key.d, key.n)
        with open(fname+'.sgn', 'wb') as fsign:
            fsign.write(str(s))


if __name__ == '__main__':
    import argparse
    import os

    #gen_keys()
    pub, priv = get_keys()
    # Parse the incoming arguments
    parser = argparse.ArgumentParser(description='Digital signature')

    parser.add_argument('input', nargs='?',
             help='input file to sign')
    parser.add_argument('mode', nargs='?',
             help='create or check signature')

    args = parser.parse_args()

    if os.path.isfile(args.input):
        if args.mode == 'create':
            sig_create(args.input, priv)
            print 'Created!'
        elif args.mode == 'check':
            print sig_check(args.input, pub)
        else:
            print "Wrong parameters"
    else:
        print "Wrong file name"

