#!/usr/bin/env python

# Author: Abraham Fernandez
# March 2016
# This script generates a chain from a sp to a distinguished point (ep)

import pandas as pd
import time 
import des_keys as dk
import binascii


#Choose an starting point
csp = '0000004819493b62'
#Choose a function to apply after every encryption
func = 13
#Known plaintext
P = 'abcdefgh'

weak_mask = 0x000000ffffffffff  #Mask to weaken DES
dist_mask = 0x000000000000007f  #Mask to identify the distinguished point
dist_pt   = 0x0
point     = 0xffffffffffffffff

key = binascii.unhexlify(csp)
chain = pd.DataFrame()

l = 0

while ( (point & dist_mask) != dist_pt ): 

    if l == 0:  #Take the sp as is, do not apply any function on it
        ki, point, point_hex_i = dk.mask(key, weak_mask, 0)
    else: 
        ki, point, point_hex_i = dk.mask(key, weak_mask, func)

    l = l + 1

    #Encrypt same plaintext with new key    
    key = dk.encrypt(ki, P)

    ko, point, point_hex_o = dk.mask(key, weak_mask, 0)
    #print 'ko{}: {}'.format(l, dk.hex_key(ko, weak_mask)) 

    entry = pd.DataFrame([[point_hex_i, point_hex_o]] , columns=['ki','ko'])
    chain = chain.append(entry, ignore_index=True)


#print 'Chain reconstructed!' 
pd.set_option('max_rows',500)
print chain
