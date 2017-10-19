Lookup tables can leak sensitive information as processors are quicker to retrieve information from a recently used address than one that has not been accessed in a while. One can use this as part of a side-channel attack to figure out the plaintext or encryption key. This can be eliminated by using non data-dependent lookup tables.

For hardware implementations of AES, storing the s-box on a chip is costly, so s-box is calculated for each operation (sounds even more costly).
