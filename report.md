Issues:
    Issue with matrix multiplication and interger overflow. Rust would complain that multiplying matrices in the mix_columns step would cause integer overflow, even that that's exactly what was wanted.
    I ended up first converting the matrix to unsigned 32-bit integers, multiplying them, then converting back to hexadecimal using a modulo operator to handle the wrapping after the fact.
