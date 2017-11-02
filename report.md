Issues:
    Issue with matrix multiplication and interger overflow. Rust would complain that multiplying matrices in the mix_columns step would cause integer overflow, even that that's exactly what was wanted.
    I ended up first converting the matrix to unsigned 32-bit integers, multiplying them, then converting back to hexadecimal using a modulo operator to handle the wrapping after the fact.

---

Lookup tables can leak sensitive information as processors are quicker to retrieve information from a recently used address than one that has not been accessed in a while. One can use this as part of a side-channel attack to figure out the plaintext or encryption key. This can be eliminated by using non data-dependent lookup tables.

For hardware implementations of AES, storing the s-box on a chip is costly, so s-box is calculated for each operation (sounds even more costly).

---

Key expansion. Learned that you never actually use the first, 0x8d, thing of the RCON.

You can also just generate the values from the rcon in real time, rather than storing it for use later. This is useful for chips with not much RAM. Same goes for the other stuff like the Sbox I think, but it's easier implementation to just store everything.
