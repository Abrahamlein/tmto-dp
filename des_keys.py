#!/usr/bin/env python

# Author: Abraham Fernandez
# March 2016

import binascii
from Crypto.Cipher import DES
import random


def hex_key ( k, wmask):
    #Convert to a string in hex
    k1 = binascii.hexlify(k)

    #Cast the number as a hex integer and mask it  
    k2 = int(k1,16) & wmask
     
    #Removes '0x' from the string
    l1 = hex(k2)[2:]

    #Removes the 'L' from the string
    if ( l1[len(l1)-1] == 'L' ):
        l1 = l1[0:len(l1)-1]

    k5 = l1.zfill(16)

    return k5



def mask ( ki, wmask, f ):
    #Convert to a string in hex
    k1 = binascii.hexlify(ki)
    #print 'k1: {}'.format(k1)
    #Cast the number as a hex integer and mask it  
    # f is different for every chain, meant to avoid collisions
    k2 = ( int(k1,16) + f ) & wmask
    
    #print 'k2: {}'.format(k2)
    
    pi = k2
 
    #Removes '0x' from the string
    l1 = hex(k2)[2:]

    #Removes the 'L' from the string
    if ( l1[len(l1)-1] == 'L' ):
        l1 = l1[0:len(l1)-1]
        #print l1

    k5 = l1.zfill(16)

    #DEBUG
    #print 'ki : {}'.format(k5)   
    
    dk = binascii.unhexlify(k5)
    #print 'dk {}'.format(dk)
    #return dk, pi, k2
    return dk, pi, k5



def randk ( oldk, wmask ):
    #Convert to a string in hex
    k1 = binascii.hexlify(oldk)
    #Generate a random number to get a new key      
    r = random.randint(0,0xffffffffffffffff)         #print 'r {}'.format(r)    
    #Cast the number as a hex integer and mask it     
    k2 = ( int(k1,16) + r ) & wmask
    #Remove the '0x' and insert leading zeros   
    k3 = hex(k2)[2:].zfill(17)
    #Take only the 16 bytes (64 bits)
    k4 = k3[0:16] 
    #print 'new rand key: {}'.format(k4) 
    #time.sleep(1)
    #Convert back to the ascii string    
    newk = binascii.unhexlify(k4)
    
    return newk


def encrypt ( key , P ):
    cipher = DES.new(key, DES.MODE_ECB)
    cipher_txt = cipher.encrypt(P)    

    return cipher_txt

