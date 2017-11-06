A 2-4 page write up explaining your code design and implementation.

# Write up

Andrew Morgan, 2017
CSE 178

## Rust as a language

I decided to write my AES implementation in Rust, as it's a language I've heard very much about in the past few years but have never actually created a project in. I find one can read and watch tutorials about a programming language all they like, but they won't actually understand or get a feel for that language until they've done a project in it. For this reason, I've decided to do my implementation of AES in Rust.

I actually took me quite a while to get used to Rust. It's syntax is familiar but different from other programming languages, though it has all the common structures: objects, loops, conditional statements, etc. The main part of Rust that threw me for a loop for often than not was its idea of ownership. Rust has its own style of memory management that does away with garbage collection. Instead, at any given time, you can only have a single object pointing to a place in memory. You can create unlimited references (like pointers) to this object, but at any one time there cannot be more than one variable that refers directly to a point in memory. If you try to set another variable to this point in memory, that is called a 'move', and the original variable that pointed to it will no longer have a value associated with it.

## Implementation and Design

All implementations of AES-128-ECB follow the same generic outline. There are four main methods, AddRoundKey, SubBytes, ShiftRows and MixColumns. You have 10 rounds, one initial with only the AddRoundKey step, 8 with all main methods and a final round that lacks MixColumns. Outside of this, you also need to generate the key blocks used in the AddRoundKey step. This process, which uses the originally provided encryption key, derives multiple 128-bit blocks, which are then XOR'd to the state in the AddRoundKey step.

I looked at some example implementations online that mostly used arrays to store the contents of the state and round keys. This was harder for me to conceptualize, however, as most of the images of the state block I had seen was a 4x4 matrix. I thus found a crate (external library) for Rust that had an implementation of matricies, including several operations such as multiply. Although not as elegant in some places compared to a single array, working with matricies which I could grab from using (row,col) calls was desirable versus just a one-dimensional array. I also used matricies to store the preset elements of AES, such as the RCON and the S-BOX.

When I was initially looking at the AES algorithm, I was confused about where people were getting the values for the RCON and S-BOX. As it turned out, those values are the same across all implementations of AES, and are designed to prevent against certain cryptographic attacks against the algorithm. 

Matrix useful to reference row/col. Only use first 11 values of RCON. Don't use first value of RCON.



---

Lookup tables can leak sensitive information as processors are quicker to retrieve information from a recently used address than one that has not been accessed in a while. One can use this as part of a side-channel attack to figure out the plaintext or encryption key. This can be eliminated by using non data-dependent lookup tables.

For hardware implementations of AES, storing the s-box on a chip is costly, so s-box is calculated for each operation (sounds even more costly).

---

Key expansion. Learned that you never actually use the first, 0x8d, thing of the RCON.

You can also just generate the values from the rcon in real time, rather than storing it for use later. This is useful for chips with not much RAM. Same goes for the other stuff like the Sbox I think, but it's easier implementation to just store everything.

---

Environment variable was to allow debugging and allow my tool to show correct step-by-step for any input.
