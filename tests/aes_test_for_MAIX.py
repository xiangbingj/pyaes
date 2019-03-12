#!env python3
from Crypto.Cipher import AES as KAES
from Crypto.Util import Counter as KCounter
import os, time
import argparse
import binascii
import sys
from enum import Enum

def print_hex(str, mode, bytes):
    for i in bytes:
        print(str, mode, ":", binascii.hexlify(i))

class cipher_type:
    class encrypt(Enum):
        ENCRYPT = 0x0
        DECRYPT = 0x1

    class aes_type(Enum):
        ECB = 0x0
        CBC = 0x1
        CFB = 0x3
        OFB = 0x4
        CRT = 0x5

def output_file(filename,num, encrypt_sel, mode, aes_key, aes_iv, data_len, indata, outdata):
    cur_cwd = os.getcwd()
    #filename = cipher_type.encrypt(encrypt_sel).name
    if encrypt_sel == 1:
        num += 1
    filename = filename+str(num)
    if not os.path.exists(filename):
        os.mkdir(filename)
    os.chdir(filename)
    key_len = len(aes_key)
    try:
        fp_cfg = open('AES_CFG.txt', 'w+')
        fp_cfg.seek(0)
        fp_in = open('AES_IN.txt', 'w+')
        fp_in.seek(0)
        fp_out = open('AES_OUT.txt', 'w+')
        fp_out.seek(0)
    except IOError:
        print('The data file is missing!')
    #print("encrypt_sel", encrypt_sel, file=fp_cfg)
    #print("aes_ci_pher_mode", mode, file=fp_cfg)
    #print("aes_key_mode", bin(mode), file=fp_cfg)
    print("encrypt_sel", '%x'%encrypt_sel, file=fp_cfg)
    print("aes_ci_pher_mode", '%x'%mode, file=fp_cfg)
    print("aes_key_mode", '%x'%key_size, file=fp_cfg)
    if key_len == 16:
        print("aes_key_sw_0", binascii.hexlify(aes_key[0:4]).decode('utf-8'), file=fp_cfg)
        print("aes_key_sw_1", binascii.hexlify(aes_key[4:8]).decode('utf-8'), file=fp_cfg)
        print("aes_key_sw_2", binascii.hexlify(aes_key[8:12]).decode('utf-8'), file=fp_cfg)
        print("aes_key_sw_3", binascii.hexlify(aes_key[12:16]).decode('utf-8'), file=fp_cfg)
    elif key_len == 24:
        print("aes_key_sw_0", binascii.hexlify(aes_key[0:4]).decode('utf-8'), file=fp_cfg)
        print("aes_key_sw_1", binascii.hexlify(aes_key[4:8]).decode('utf-8'), file=fp_cfg)
        print("aes_key_sw_2", binascii.hexlify(aes_key[8:12]).decode('utf-8'), file=fp_cfg)
        print("aes_key_sw_3", binascii.hexlify(aes_key[12:16]).decode('utf-8'), file=fp_cfg)
        print("aes_key_sw_4", binascii.hexlify(aes_key[16:20]).decode('utf-8'), file=fp_cfg)
        print("aes_key_sw_5", binascii.hexlify(aes_key[20:24]).decode('utf-8'), file=fp_cfg)
    elif key_len == 32:
        print("aes_key_sw_0", binascii.hexlify(aes_key[0:4]).decode('utf-8'), file=fp_cfg)
        print("aes_key_sw_1", binascii.hexlify(aes_key[4:8]).decode('utf-8'), file=fp_cfg)
        print("aes_key_sw_2", binascii.hexlify(aes_key[8:12]).decode('utf-8'), file=fp_cfg)
        print("aes_key_sw_3", binascii.hexlify(aes_key[12:16]).decode('utf-8'), file=fp_cfg)
        print("aes_key_sw_4", binascii.hexlify(aes_key[16:20]).decode('utf-8'), file=fp_cfg)
        print("aes_key_sw_5", binascii.hexlify(aes_key[20:24]).decode('utf-8'), file=fp_cfg)
        print("aes_key_sw_6", binascii.hexlify(aes_key[24:28]).decode('utf-8'), file=fp_cfg)
        print("aes_key_sw_7", binascii.hexlify(aes_key[28:32]).decode('utf-8'), file=fp_cfg)
    else:
        raise Exception('Failed case (%s)' % key_len)
    print("aes_iv_0", binascii.hexlify(aes_iv[0:4]).decode('utf-8'), file=fp_cfg)
    print("aes_iv_1", binascii.hexlify(aes_iv[4:8]).decode('utf-8'), file=fp_cfg)
    print("aes_iv_2", binascii.hexlify(aes_iv[8:12]).decode('utf-8'), file=fp_cfg)
    print("aes_iv_3", binascii.hexlify(aes_iv[12:16]).decode('utf-8'), file=fp_cfg)
    print("aes_pc_num", '%x'%(data_len-1), file=fp_cfg)
    fp_cfg.close()
    for i in indata:
        #print(str, mode, ":", binascii.hexlify(i))
        print(binascii.hexlify(i[0:4]).decode('utf-8'), file=fp_in)
        print(binascii.hexlify(i[4:8]).decode('utf-8'), file=fp_in)
        print(binascii.hexlify(i[8:12]).decode('utf-8'), file=fp_in)
        print(binascii.hexlify(i[12:16]).decode('utf-8'), file=fp_in)
    fp_in.close()
    for i in outdata:
        print(binascii.hexlify(i[0:4]).decode('utf-8'), file=fp_out)
        print(binascii.hexlify(i[4:8]).decode('utf-8'), file=fp_out)
        print(binascii.hexlify(i[8:12]).decode('utf-8'), file=fp_out)
        print(binascii.hexlify(i[12:16]).decode('utf-8'), file=fp_out)
    fp_out.close()
    os.chdir(cur_cwd)

def aes_test(filename, num, mode, key_size, number):
    test = number
    key = os.urandom(key_size // 8)
    aes_key = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
    aes_iv = b'\x10\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01'
    if mode == 'CBC':
        cipher_mode = 1
        iv = os.urandom(16)
        plaintext = [os.urandom(16) for x in range(0, test)]
        plaintext_len = test * 16
        t0 = time.time()
        kaes = KAES.new(key, KAES.MODE_CBC, IV=iv)
        kaes2 = KAES.new(key, KAES.MODE_CBC, IV=iv)
    elif mode == 'CFB':
        cipher_mode = 3
        #iv = os.urandom(16)
        iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        key = b'\x64\xcf\x9c\x7a\xbc\x50\xb8\x88\xaf\x65\xf4\x9d\x52\x19\x44\xb2'
        #plaintext = [os.urandom(16) for x in range(0, test)]
        plaintext = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        #plaintext = ['00000000000000000000000000000000']
        plaintext = [plaintext]
        for i in plaintext:
            print("plaintext:", binascii.hexlify(i))
        plaintext_len = 16
        kaes = KAES.new(key, KAES.MODE_CFB, IV=iv, segment_size=16*8)
        kaes2 = KAES.new(key, KAES.MODE_CFB, IV=iv, segment_size=16*8)
        ciphertext = [KAES.new(key=key, mode=KAES.MODE_CFB, iv=iv, segment_size=16*8).encrypt(p) for p in plaintext]
        for i in ciphertext:
            print("ciphertext:", binascii.hexlify(i))
    elif mode == 'OFB':
        cipher_mode = 4
        iv = os.urandom(16)
        plaintext = [os.urandom(16) for x in range(0, test)]
        plaintext_len = test * 16
        kaes = KAES.new(key, KAES.MODE_OFB, IV=iv)
        kaes2 = KAES.new(key, KAES.MODE_OFB, IV=iv)
    elif mode == 'ECB':
        cipher_mode = 0
        plaintext = [os.urandom(16) for x in range(0, test)]
        plaintext_len = test * 16
        kaes = KAES.new(key, KAES.MODE_ECB)
        kaes2 = KAES.new(key, KAES.MODE_ECB)
    elif mode == 'CTR':
        cipher_mode = 5
        text_length = \
            [None, 3, 16, 127, 128, 129, 1500, 10000, 100000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008][
                test]
        if test < 6:
            plaintext = [os.urandom(text_length)]
        else:
            plaintext = [os.urandom(text_length) for x in range(0, test)]
        plaintext_len = test * text_length
        kaes = KAES.new(key, KAES.MODE_CTR, counter=KCounter.new(128, initial_value=0))
        kaes2 = KAES.new(key, KAES.MODE_CTR, counter=KCounter.new(128, initial_value=0))

    ciphertext = [kaes.encrypt(p) for p in plaintext]
    output_file(filename=filename, num=num, encrypt_sel=0, mode=cipher_mode, aes_key=key, aes_iv=iv, data_len=plaintext_len,
                indata=plaintext,
                outdata=ciphertext)
    for i in ciphertext:
        print("ciphertext:", binascii.hexlify(i))
    decrypttext = [kaes2.decrypt(k) for k in ciphertext]
    for i in decrypttext:
        print("decrypttext:", binascii.hexlify(i))
    if plaintext != decrypttext:
        print("Test: mode=%s operation=decrypt key_size=%d text_length=%d trial=%d" % (
            mode, key_size, len(plaintext), test))
        raise Exception('Failed decypt test case (%s)' % mode)
    else:
        output_file(filename=filename, num=num, encrypt_sel=1, mode=cipher_mode, aes_key=key, aes_iv=iv,
                    data_len=plaintext_len,
                    indata=ciphertext,
                    outdata=decrypttext)
    print("get aes data !!")

if __name__ == '__main__':
    #for mode in ['CFB', 'OFB']:
    mode = 'CFB'
    case = 0
    if mode == 'OFB':
        case = 60
    for key_size in [128, 192, 256]:
        for test in range(1, 2):
            cur_cwd = os.getcwd()
            #filename = mode + '_' + str(key_size)
            #filename = mode + '_CAES'
            filename = 'case'
            #if not os.path.exists(filename):
            #    os.mkdir(filename)
            #os.chdir(filename)
            aes_test(filename=filename, num=case, mode=mode, key_size=key_size, number=test)
            #os.chdir(cur_cwd)
            case += 2
