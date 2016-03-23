#!/usr/bin/env python

# Author: Abraham Fernandez
# March 2016
# Description: This script generates a table with m number of sp/ep pairs using DES
# as block cypher. DES i/o can be weakened for practical learning purposes.


import pandas as pd
import time 
import des_keys as dk
import binascii
import progressbar

from datetime import datetime
start_time = datetime.now()

reload(dk)

weak_mask = 0x000000ffffffffff  #Mask to weaken DES, all f's means no weakening
dist_mask = 0x000000000000007f  #Mask to identify the distinguished point
                                #If the dist. pt. is very narrow, DES might get stuck in a loop.
dist_pt   = 0x0
point = 0xffffffffffffffff

entries = 100     # m chains
nfunc = 16          #Number of pattern functions to avoid collisions

#Use a random initial key
key = '12345678'
#Known plaintext
P = 'abcdefgh'

first_pt = 1
func = 0 

# Chop chains to no more than max_len
chain_len = 0 
max_len = 1000  # Maximun t, the minimun depends on the dist. point

table = pd.DataFrame()

bar = progressbar.ProgressBar(maxval=entries, \
    widgets=[progressbar.Bar('#', '[', ']'), ' ', progressbar.Percentage()])
bar.start()

for i in range(0,entries):
    
    if func == nfunc:   #Reuse the same pattern functions
        func = 0

    #Loop until a distinguised point is found
    while ( ((point & dist_mask) != dist_pt) & (chain_len != max_len) ):
        chain_len = chain_len + 1 
        kn, point, point_hex = dk.mask(key, weak_mask, func)
        
        if first_pt == 1:
            sp = point_hex  #Store the starting point
            first_pt = 0 

        #Encrypt same plaintext with new key    
        key = dk.encrypt(kn, P)
        kn, point, point_hex = dk.mask(key, weak_mask, 0)
     
    #Store the endpoint
    ep = point_hex
    chain_len = 0
    func = func + 1
    bar.update(i+1)
      
    entry = pd.DataFrame([[sp, ep]] , columns=['sp','ep'])
    table = table.append(entry, ignore_index=True)

    #Generate a new key and calculate a new chain
    key = dk.randk(key, weak_mask)
    point = 0xffffffffffffffff
    first_pt = 1

#table = table.sort_values(by="ep", ascending=True)
table.to_json('table.json')

bar.finish()
print 'Table generated!' 

end_time = datetime.now()
print('Duration: {}'.format(end_time - start_time))

