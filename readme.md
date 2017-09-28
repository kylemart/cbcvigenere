# C-CBC Vigenere

## About

A simple, lightweight, C-based program that encrypts files using a [Vigenere Cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher) in [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) mode.

## Usage

The program receives three space-seperated command line arguments:
1. *Filename* - name of the file to encrypt
2. *Keyword* - keyword used by the cipher
3. *Initialization Vector* - [initialization vector](https://en.wikipedia.org/wiki/Initialization_vector) required to initiate cipher block chaining

> Note: The length of the keyword and initialization vector must be the same. Furthermore, both strings must be comprised of only lowercase letters. Deviating from these restrictions will result in error.

Here's an example that illustrates the format of the command:

`~ ➜ ./cbcv plain.txt secret asdfgh`

## Output Format

The program outputs a set of statistical data, filtered plaintext, and ciphertext to stdout. To be exact, the report will contain:
* Filename
* Vigenere keyword
* Initialization vector
* Plaintext
* Ciphertext
* Number of characters in the plaintext
* Block size
* Number of pad characters added
