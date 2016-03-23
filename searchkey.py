#!/usr/bin/env python

# Author: Abraham Fernandez
# March 2016
# This script takes a 64b ciphertext and looks for its corresponding key
# in the previously generated table.

import pandas as pd
import time 
import des_keys as dk
import binascii
import random
import progressbar

from datetime import datetime
start_time = datetime.now()

spep_table = pd.read_json('table.json')

#Find the key for this ciphertext:
ciphertext = '00000020ef76935a'
key = binascii.unhexlify(ciphertext)
#Known plaintext
P = 'abcdefgh'

nfunc = 16      #Number of "pattern" functions to avoid collisions

weak_mask = 0x000000ffffffffff  #Mask to weaken DES
dist_mask = 0x000000000000007f  #Mask to identify the distinguished point
dist_pt   = 0x0
point     = 0xffffffffffffffff


# This data frame will be a subset of the whole table
cand_chains = pd.DataFrame()
# This Data frame will have all candidate keys' sp/ep
cand_keys = pd.DataFrame()
first_try = 1
	
bar = progressbar.ProgressBar(maxval=nfunc, \
    widgets=[progressbar.Bar('#', '[', ']'), ' ', progressbar.Percentage()])
bar.start()

for func in range(0,nfunc):     #Try all the functions for that key
    
    #Iterate one function until it gets to a distinguished point
    while ( (point & dist_mask) != dist_pt ): 
 
        kn, point, point_hex = dk.mask(key, weak_mask, func)

        if first_try == 1:
            sp = point_hex  #Store the starting point
            first_try = 0 
    
        #Encrypt same plaintext with new key    
        key = dk.encrypt(kn, P)
        kn, point, point_hex = dk.mask(key, weak_mask, 0) 


    first_try = 1
    ep = point_hex  #Store the endpoint

    #Check if the distinguished point is in the table
    match = spep_table['ep'].str.contains(point_hex)
  
    #If it is, spep_table[match] will not be empty
    if (spep_table[match].empty == False):
        
        #Get the index of the matching element            
        index = int(spep_table[match].index.tolist()[0])
        
        #Confirm that it was generated with the same function
        if (index % nfunc) == func:

            #Store it as a candidate                 
            cand_chains = cand_chains.append(spep_table[match], ignore_index=True)
            entry = pd.DataFrame([[sp, ep, func]] , columns=['sp','ep','f'])
            cand_keys = cand_keys.append(entry, ignore_index=True)
    else:
        pass
        #print 'No match: {}'.format( point_hex )    

    #Reset the key to generate another chain using a different function    
    key = binascii.unhexlify(ciphertext)
    point = 0xffffffffffffffff    
    bar.update(func+1)

bar.finish()

if ( cand_keys.empty == True ):
    print 'No match found!' 

else:   #Regenerate all the candidate chains

    num_cand_chains = cand_chains.shape[0]
    num_cand_keys   = cand_keys.shape[0]
    
    pd.set_option('max_rows',10)

    #For each candidate key, generate all the candidate chains
    for k in range(0, num_cand_keys):
        
        func = cand_keys.loc[k,'f']
        for c in range(0, num_cand_chains):
            
            #Check every key in the candidate chains frame
            csp = cand_chains.loc[c,'sp']
            key = binascii.unhexlify(csp)
            chain = pd.DataFrame()

            l = 0
            ki, point, point_hex_i = dk.mask(key, weak_mask, 0)

            #Regenerate the chain from sp to distinguished point
            while ( (point & dist_mask) != dist_pt ): 

                if l == 0:  #Take the sp as is, do not apply any function on it
                    ki, point, point_hex_i = dk.mask(key, weak_mask, 0)
                else: 
                    ki, point, point_hex_i = dk.mask(key, weak_mask, func)


                #Encrypt same plaintext with new key    
                key = dk.encrypt(ki, P)

                ko, point, point_hex_o = dk.mask(key, weak_mask, 0) 

                #Store the chain
                entry = pd.DataFrame([[point_hex_i, point_hex_o]] , columns=['ki','ko'])
                chain = chain.append(entry, ignore_index=True)  

                #Check if the ciphertext matches, if so, the key might have been found.
                if point_hex_o == ciphertext:
                    print 'key found: {} at index: {}'.format(point_hex_i, l)
                    print chain.ix[l]

                l = l + 1
            
            #print chain
                  
end_time = datetime.now()
print('Duration: {}'.format(end_time - start_time))
