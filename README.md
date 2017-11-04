Rust-AES
========

This repository currently serves as a place to host my AES binary.

## Why should you care

This tool will allow you to quickly convert any given input text and key into AES-128-ECB ciphertext. It will also show you the state block at every step of the AES process, which you can use to compare with your own algorithm.

## Use

To run the tool, navigate to the containing directory from within your terminal, and execute it:

```
$ chmod 755 ./aes #Set appropriate permissions if necessary
$ ./aes
Andrew Morgan (2017) - CSE 178
😃 Type anything and press enter...
> hi

Result: 
5f 5b 3e c3 69 62 4e a7 00 e7 78 54 8d f1 62 da 

>
```

To show the complete steps of the encryption process, simply write `debug` after the `aes` command:

```
$ ./aes debug
Andrew Morgan (2017) - CSE 178
😃 Type anything and press enter...
> hi
...
Encrypting state block:
|68|00|00|00|
|69|00|00|00|
|00|00|00|00|
|00|00|00|00|

Round Key chunk is:
|30|34|38|63|
|31|35|39|64|
|32|36|61|65|
|33|37|62|66|

After first AddRoundKey:
|58|34|38|63|
|58|35|39|64|
|32|36|61|65|
|33|37|62|66|

After SubBytes:
|6a|18|07|fb|
|6a|96|12|43|
|23|05|ef|4d|
|c3|9a|aa|33|

After ShiftRows: 
|6a|18|07|fb|
|96|12|43|6a|
|ef|4d|23|05|
|33|c3|9a|aa|

After MixColumns: 
|a9|88|72|fc|
|44|28|7e|8a|
|6c|ce|b7|7e|
|a1|ea|46|36|

...

After AddRoundKey: 
|5f|69|00|8d|
|5b|62|e7|f1|
|3e|4e|78|62|
|c3|a7|54|da|

State block is now encrypted:
|5f|69|00|8d|
|5b|62|e7|f1|
|3e|4e|78|62|
|c3|a7|54|da|


Result: 
5f 5b 3e c3 69 62 4e a7 00 e7 78 54 8d f1 62 da 

> 
```

By default, the encryption key is `0123456789abcef`. If you would like to use a custom key, specify it on the command line:

```
$ ./aes myown_custom_key
Andrew Morgan (2017) - CSE 178
😃 Type anything and press enter...
> hi

Result: 
5e 47 82 9f c9 62 fe bc e4 0d 32 c7 6a e1 59 31 

> 
```

Note that encryption keys are not padded, and length must be a multiple of 16.

## Source Code

Source code will be available after the project's deadline on November 20th. Good luck!
