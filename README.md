# tmto-dp
Hellman's Time Memory Trade Off using distinguished point to break DES

This is a *sketchy* implementation of the Hellman's TMTO.  It works with DES, but with a few changes it could be applied to another block cipher. Several improvements can be done, like sorting the EP as they are found, and doing a binary search when looking up an EP. There are some variables that can be removed or reused for debugging purposes. 

References:
+ Martin E. Hellman. A Cryptanalytic Time - Memory Trade-Off. 
+ Philippe Oechslin. Making a Faster Cryptanalytic Time-Memory Trade-Off. Pp. 3,4.
+ D.E. Denning. Cryptography and Data Security, Pg. 100.
