extern crate numrs;
extern crate hex;
extern crate openssl;

use std::io::prelude::*;

use std::io;
use hex::ToHex;
use numrs::matrix;
use numrs::matrix::Matrix;

fn get_sbox() -> Matrix<u8> {
    let sbox = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16];

    let sbox = matrix::from_elems(16, 16, &sbox);
    sbox
}

/*
 * Round constant word array, Rcon.
 * Only first 11 values are used for AES-128.
 */
fn get_rcon_col(col: usize) -> Matrix<u8> {
    let rcon = [
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    let rcon = matrix::from_elems(4, 1, &[rcon[col], 0, 0, 0]);
    rcon
}

/*
 * matrix_row_rotate: Helper function to rotate a row of bytes a given
 * amount of iterations from left-to-right
 */
fn matrix_row_rotate(m: &mut Matrix<u8>, row: usize, iters: usize) {
    // Reduce the amount of iterations to a value between 0-3 inclusive
    let iterations = iters % 4;

    for _ in 0..iterations {
        // Move the first item to the last place, and shift everything left.
        let row_nums = [m.get(row,1), m.get(row,2), m.get(row,3), m.get(row,0)];

        // Place the shifted row_nums number back in
        for col in 0..4 {
            m.set(row, col, row_nums[col]);
        }

        //print_matrix(&m);
    }
}

/*
 * shift_rows: Performs the ShiftRows operation of Rijndael
 * For each row, depending on its depth, we shift it by that number
 */
fn shift_rows(state: &mut Matrix<u8>) {
    for depth in 1..state.num_rows() {
        matrix_row_rotate(state, depth, depth);
    }
}

fn mix_single_column(col: &mut[u8; 4]) {
    // Ref: https://en.wikipedia.org/wiki/Rijndael_MixColumns
    // The array 'a' is simply a copy of the input array col
    // The array 'b' is each element of the array 'a' multiplied by 2
    // in Rijndael's Galois field
    let mut a = [0u8; 4];
    let mut b = [0u8; 4];

    // a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field
    for c in 0..4 {
        a[c] = col[c];

        // h is 0xff if the high bit of r[c] is set, 0 otherwise
        let h = ((col[c] as i8) >> 7) as u8;

        // implicitly removes high bit because b[c] is an 8-bit char,
        // so we xor by 0x1b and not 0x11b in the next line
        b[c] = col[c] << 1; 
        b[c] ^= 0x1b & h; // Rijndael's Galois field
    }
    col[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; // 2 * a0 + a3 + a2 + 3 * a1
    col[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; // 2 * a1 + a0 + a3 + 3 * a2
    col[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; // 2 * a2 + a1 + a0 + 3 * a3
    col[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; // 2 * a3 + a2 + a1 + 3 * a0
}

fn mix_columns(state: &mut Matrix<u8>) {
    for col in 0..state.num_cols() {
        // Get a column from the state matrix
        let mut m_col = [state.get(0, col),
                         state.get(1, col),
                         state.get(2, col),
                         state.get(3, col)];

        // Perform mix column
        mix_single_column(&mut m_col);

        // Substitute the result for the original column in the state
        for row in 0..state.num_rows() {
            state.set(row, col, m_col[row]);
        }
    }
}

fn xor_matricies(m1: &mut Matrix<u8>, m2: & Matrix<u8>) {
    let v1 = m1.get_vec();
    let v2 = m2.get_vec();
    let length = m1.num_rows() * m1.num_cols();

    let mut temp_vec = Vec::new();
    let mut index = 0;

    for i in 0..length {
        temp_vec.push(v1[i] ^ v2[i]);
    }
    for i in 0..m1.num_rows() {
        for j in 0..m1.num_cols() {
            let val = temp_vec[index];
            m1.set(i, j, val);
            index += 1;
        }
    }
}

fn key_expansion(round_key: &mut Matrix<u8>, key: &Matrix<u8>) {
    // The first round key is the key itself
    for i in 0..round_key.num_rows() {
        round_key.set(0, i, key.get(0, i));
        round_key.set(1, i, key.get(1, i));
        round_key.set(2, i, key.get(2, i));
        round_key.set(3, i, key.get(3, i));
    }

    // All other round keys are found from the previous round keys
    for i in 4..4*10 {
        let mut col = matrix::from_elems(1, 4, &[round_key.get(0, (i-1)),
                                                 round_key.get(1, (i-1)),
                                                 round_key.get(2, (i-1)),
                                                 round_key.get(3, (i-1))]);

        if i % 4 == 0 {
            // Shift the 4 bytes in a word to the left once
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
            matrix_row_rotate(&mut col, 0, 0);

            // Substitue the bytes within the column using the contents of the s-box
            sub_bytes(&mut col);

            // xor the col with the respective rcon column
            xor_matricies(&mut col, &get_rcon_col((i / 4) - 1));
        }

        // xor the col with the previous i-4 col of the round key
        let init_col = matrix::from_elems(1, 4, &[round_key.get(0, (i-4)),
                                                  round_key.get(1, (i-4)),
                                                  round_key.get(2, (i-4)),
                                                  round_key.get(3, (i-4))]);
        xor_matricies(&mut col, &init_col);
    }
}

/*
 * sub_bytes: performs the SubBytes operation of Rijndael
 * SubBytes substitues an item in the state with another in the s-box,
 * depending on the first and second characters of the hexadecimal byte
 * contained at a specific row and col in the state.
 * The s-box is the same for all implementations of aes.
 */
fn sub_bytes(state: &mut Matrix<u8>) {
    let sbox = get_sbox();
    for i in 0..state.num_rows()  {
        for j in 0..state.num_cols()  {
            let byte = state.get(i, j);

            // Get the first and second component of the byte
            let hex_col = byte & 0x0f;
            let hex_row = (byte & 0xf0) / 0x10;

            // Now get the corresponding row,col from the sbox
            // And overwrite the state with it
            state.set(i, j, sbox.get((hex_row as usize), (hex_col as usize)));
        }
    }
}

fn encrypt_state_block(state: &mut Matrix<u8>, round_key: &Matrix<u8>) {
    // Initial round
    xor_matricies(state, round_key);

    // Intermediate and final round
    for round in 0..10 {
        sub_bytes(state);
        shift_rows(state);
        if round != 9 {mix_columns(state);}
        xor_matricies(state, round_key);
    }
}

fn decode_and_append(state: &Matrix<u8>, string: &mut String) {
    for i in 0..state.num_rows() {
        for j in 0..state.num_cols() {
            string.push(state.get(j, i) as char);
        }
    }
}

fn aes(byte_array: &str, key: &[u8]) -> String {
    let mut encrypted_string = String::new();

    // Perform key expansion
    let key_matrix = matrix::from_elems(4, 4, key);
    let mut round_key = Matrix::new(4, 4*10, 0u8);
    key_expansion(&mut round_key, &key_matrix);

    // Loop through each 16 bytes of the provided string and encrypt separately
    let mut index = 0;
    loop {
        let mut state: Matrix<u8>;
        if index + 16 > byte_array.len() {
            // Pad rest of matrix with zeros
            state = matrix::from_elems(4, 4, &[0u8; 16]);
            for i in 0..state.num_rows() {
                for j in 0..state.num_cols() {
                    if index >= byte_array.len() {
                        break;
                    }
                    state.set(j, i, byte_array.as_bytes()[index]);
                    index += 1;
                }
            }
        } else {
            state = matrix::from_elems(4, 4, &byte_array.as_bytes()[index..index+16]);
        }

        println!("Encrypting state block:");
        print_matrix(&state);
        encrypt_state_block(&mut state, &round_key);
        decode_and_append(&state, &mut encrypted_string);

        index += 16;

        // Break once we've reached the end of the string
        if index >= byte_array.len() {
            break;
        }
    }
    encrypted_string
}

fn main() {
    let key = "0123456789abcdef".as_bytes();
    let stdin = io::stdin();

    println!("😃 Type anything and press enter...");
    let input = &mut String::new();
    loop {
        input.clear();
        print!("> ");

        #[allow(unused_must_use)]
        {
            io::stdout().flush();
            stdin.read_line(input);
        }

        if input == "" {
            println!("Empty input. Terminating...");
            break;
        }

        // Remove newline character from string
        input.pop();

        let encrypted_string = aes(&input, key);
        println!("Result: {}\n", encrypted_string.as_bytes().to_hex());
    }
}

#[allow(dead_code)]
fn print_matrix(m: &Matrix<u8>) {
    println!();
    for i in 0..m.num_rows() {
        print!("|");
        for j in 0..m.num_cols() {
            print!("{:02x}|", m.get(i,j))
        }
        println!("");
    }
}

// ------------ Tests ------------ //

#[test]
fn test_sub_bytes() {
    let state = [
        0x19, 0xa0, 0x9a, 0xe9,
        0x3d, 0xf4, 0xc6, 0xf8,
        0xe3, 0xe2, 0x8d, 0x48,
        0xbe, 0x2b, 0x2a, 0x08];

    let output = [
        0xd4, 0xe0, 0xb8, 0x1e,
        0x27, 0xbf, 0xb4, 0x41,
        0x11, 0x98, 0x5d, 0x52,
        0xae, 0xf1, 0xe5, 0x30];

    let mut state = matrix::from_elems(4, 4, &state);
    let output = matrix::from_elems(4, 4, &output);

    sub_bytes(&mut state);

    print_matrix(&state);
    print_matrix(&output);

    assert!(output == state);
}

#[test]
fn test_shift_rows() {
    let state = [
        0xd4, 0xe0, 0xb8, 0x1e,
        0x27, 0xbf, 0xb4, 0x41,
        0x11, 0x98, 0x5d, 0x52,
        0xae, 0xf1, 0xe5, 0x30];

    let output = [
        0xd4, 0xe0, 0xb8, 0x1e,
        0xbf, 0xb4, 0x41, 0x27, 
        0x5d, 0x52, 0x11, 0x98, 
        0x30, 0xae, 0xf1, 0xe5];

    let mut state = matrix::from_elems(4, 4, &state);
    let output = matrix::from_elems(4, 4, &output);

    shift_rows(&mut state);

    print_matrix(&state);
    print_matrix(&output);

    assert!(output == state);
}

#[test]
fn test_mix_columns() {
    let state = [
        0xd4, 0xe0, 0xb8, 0x1e,
        0xbf, 0xb4, 0x41, 0x27, 
        0x5d, 0x52, 0x11, 0x98, 
        0x30, 0xae, 0xf1, 0xe5];

    let output = [
        0x04, 0xe0, 0x48, 0x28,
        0x66, 0xcb, 0xf8, 0x06, 
        0x81, 0x19, 0xd3, 0x26, 
        0xe5, 0x9a, 0x7a, 0x4c];

    let mut state = matrix::from_elems(4, 4, &state);
    let output = matrix::from_elems(4, 4, &output);

    mix_columns(&mut state);

    print_matrix(&state);
    print_matrix(&output);

    assert!(output == state);
}

#[test]
fn test_xor_matricies() {
    let state = [
        0x04, 0xe0, 0x48, 0x28,
        0x66, 0xcb, 0xf8, 0x06, 
        0x81, 0x19, 0xd3, 0x26, 
        0xe5, 0x9a, 0x7a, 0x4c];

    let output = [
        0xa4, 0x68, 0x6b, 0x02,
        0x9c, 0x9f, 0x5b, 0x6a, 
        0x7f, 0x35, 0xea, 0x50, 
        0xf2, 0x2b, 0x43, 0x49];

    let round_key = [
        0xa0, 0x88, 0x23, 0x2a,
        0xfa, 0x54, 0xa3, 0x6c,
        0xfe, 0x2c, 0x39, 0x76,
        0x17, 0xb1, 0x39, 0x05];

    let mut state = matrix::from_elems(4, 4, &state);
    let output = matrix::from_elems(4, 4, &output);
    let round_key = matrix::from_elems(4, 4, &round_key);

    xor_matricies(&mut state, &round_key);

    print_matrix(&state);
    print_matrix(&round_key);
    print_matrix(&output);

    assert!(output == state);
}

#[test]
fn test_enc_dec() {
    use openssl::symm::*;
    use openssl::symm::Mode::*;

    let key = "0123456789abcdef";
    let input = "hello";
    let ciphertext = aes(&input, key.as_bytes());
    let mut decrypted = &[0u8; input.len()];

    // Decrypt the cipher
    let decrypter = Crypter::new(aes_128_ecb(), Decrypt, key.as_bytes());
    decrypter.pad(true);
    decrypter.init(Decrypt, key.as_slice(), Vec::from_elem(16,0));

    decrypter.update(ciphertext.as_bytes(), &mut decrypted);

    println!("Input: {}\nKey: {}\nCipher: {}\nDecrypted: {}", input, key, ciphertext, decrypted);
    assert!(false);
}
