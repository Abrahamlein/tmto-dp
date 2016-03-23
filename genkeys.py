#!/usr/bin/env python

# Author: Abraham Fernandez
# March 2016
# This script generates random keys, it generates a sp --> ep chain and looks up 
# the ep in the table. If found, the generated sp/ep pair is stored as well as the 
# matching sp/ep of the table.

import pandas as pd
import time 
import des_keys as dk
import binascii
import random
import progressbar

spep_table = pd.read_json('table.json')

#Use a random initial key, any.
key = '1a2b3c4d'
#Known plaintext
P = 'abcdefgh'

samples = 4   #Generate this number of keys randomly
nfunc = 16      #Number of pattern functions to avoid collisions

weak_mask = 0x000000ffffffffff  #Mask to weaken DES
dist_mask = 0x000000000000007f  #Mask to identify the distinguished point
dist_pt   = 0x0
point     = 0xffffffffffffffff


# This data frame will be a subset of the whole table
cand_chains = pd.DataFrame()
# This Data frame will have all candidate keys' sp/ep
cand_keys = pd.DataFrame()
first_try = 1

# Chop chains to no more than max_len
chain_len = 0 
max_len = 1000
	
bar = progressbar.ProgressBar(maxval=samples, \
    widgets=[progressbar.Bar('#', '[', ']'), ' ', progressbar.Percentage()])
bar.start()


for i in range(0,samples):
    
    for func in range(0,nfunc):     #For every rand key, try all the functions
        
        while ( (point & dist_mask) != dist_pt & (chain_len != max_len) ): 
            chain_len = chain_len + 1
            kn, point, point_hex = dk.mask(key, weak_mask, func)
        
            if first_try == 1:
                sp = point_hex  #Store the starting point
                first_try = 0 
        
            #Encrypt same plaintext with new key    
            key = dk.encrypt(kn, P)
            kn, point, point_hex = dk.mask(key, weak_mask, 0) 


        first_try = 1
        ep = point_hex  #Store the endpoint
        chain_len = 0
        #Check if the distinguished point is in the table
        match = spep_table['ep'].str.contains(point_hex)

        #If it is, spep_table[match] will not be empty
        if (spep_table[match].empty == False):
            #Get the index of the matching element            
            index = int(spep_table[match].index.tolist()[0])
            #Confirm that it was generated with the same function
            if (index % nfunc) == func:
                #Store it as a candidate                 
                cand_chains = cand_chains.append(spep_table[match], ignore_index=False)
                entry = pd.DataFrame([[sp, ep, func]] , columns=['sp','ep','f'])
                cand_keys = cand_keys.append(entry, ignore_index=True)
        else:
            pass
            #print 'No match: {}'.format( point_hex )    

        #Take the old key and generate a new one
        key = dk.randk(key, weak_mask)
        point = 0xffffffffffffffff
    
    bar.update(i+1)

bar.finish()

if ( cand_keys.empty == True ):
    print 'No match found!' 
