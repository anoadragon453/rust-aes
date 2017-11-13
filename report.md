Andrew Morgan, 2017
CSE 178

## Rust as a language

I decided to write my AES implementation in Rust, as it's a language I've heard very much about in the past few years but have never actually created a project in. I find one can read and watch tutorials about a programming language all they like, but they won't actually understand or get a feel for that language until they've done a project with it. For this reason, I've decided to do my implementation of AES in Rust.

It actually took me quite a while to get used to Rust. Its syntax is familiar but different from other programming languages in many ways, though it has all the common structures: objects, loops, conditional statements, etc. The main part of Rust that I kept getting hung up on more often than not was its idea of ownership. Rust has its own style of memory management that does away with garbage collection. Instead of iterating through memory every so often and looking for unused memory locations, you can have, at any given time, only a single object pointing to a location in memory. 

You can create unlimited references (like pointers) to an object, but at any point there cannot be more than one variable that refers directly to a point in memory. If you try to set another variable to this point in memory, that is called a 'move', and the original variable that pointed to it will no longer have a memory location associated with it. This prevents a whole class of common runtime errors where the program tries to use or free a value that no longer exists in memory. Rust will prevent you from compiling a program that is susceptible to these issues.

## Implementation and Design of AES

All implementations of AES-128-ECB follow the same generic outline. There are four main methods, AddRoundKey, SubBytes, ShiftRows and MixColumns. You have 10 rounds, an initial one with only the AddRoundKey step, 8 with all main methods in a row and a final round that lacks the MixColumns step. Outside of this, you also need to generate the key blocks used in AddRoundKey. This process, which uses the originally provided encryption key, is called Key Expansion and derives multiple 128-bit blocks, which are then XOR'd to the state in the AddRoundKey step.

I looked at some example implementations online that mostly used arrays to store the contents of the state and round keys. However this was harder for me to conceptualize, as most of the images of the state block I had seen was a 4x4 matrix. I thus found a crate (external library in Rust) that had an implementation of matricies, including several operations such as matrix multiplication. Although not as elegant in some places compared to a single array, working with matricies which I could grab from using (row,col) calls was desirable versus just a one-dimensional array. I also used matricies to store the preset elements of AES, such as the RCON and the Substitution Box.

When I was initially looking at the AES algorithm, I was confused about where people were getting the values for the RCON and S-BOX. As it turned out, those values are the same across all implementations of AES, and are designed to prevent against certain cryptographic attacks against the algorithm. While the values of both the RCON and the S-Box can be generated on the fly, which is preferred for low-memory devices, I decided to simply include the necessary values directly in the source code, stored as Rust matricies. In the case of the RCON, in AES-128-ECB only the first 11 values (sans the first) are used, and thus that is all I included.

These matricies were very easy to work with. While allowing for simple row, column getting and setting, the matrix implementation also featured simple matrix multiplication, which came in very handy during the MixColumns step, where each column of the state would need to be multiplied by the fixed matrix. This turned the otherwise multi-line implementation into only a single line.

---

Lookup tables can leak sensitive information as processors are quicker to retrieve information from a recently used address than one that has not been accessed in a while. One can use this as part of a side-channel attack to figure out the plaintext or encryption key. This can be eliminated by using non data-dependent lookup tables.

Talk about command line input. To allow debugging and allow my tool to show correct step-by-step for any input. Also to change key. Goes under design.
