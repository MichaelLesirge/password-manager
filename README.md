# password-manager
My super simple CLI password manager. Just for learning about cryptography and steganography, don't actually save your passwords here.

## Encryption
<img align="right" alt="Round in AES" src="https://github.com/michael-lesirge/password-manager/assets/100492377/e42e6649-428c-450a-bbca-b60609bf0eac" width = 200>
<p>This project focuses on the implementation of Advanced Encryption Standard (AES) encryption. AES is a widely used symmetric encryption algorithm, meaning you use one key to encrypt and decrypt the data. AES is a iterated block cipher, meaning that it encrypts and decrypts a block of data by the iteration or round of a specific transformation. I implement it using Python 3 with the goal of getting a better understanding of cryptography after being inspired by a Computerphile video on it.</p>
<p>I made my implementation from scratch using zero imports. I also tried to avoid using hardcoded lookup tables and instead tried to compute the values myself so I actually understood where those values came from, and why they needed to be that.</p>

<a href="https://www.youtube.com/watch?v=O4xNJsjtN6E">AES Encryption Video</a>

## Steganography
<img align="right" alt="Steganography image" src="https://github.com/michael-lesirge/password-manager/assets/100492377/efb4c10e-1c82-4667-b759-b75742ad3ed6" width = 300>
<p>I decided to also create functions for basic steganography on Portable Network Graphics (PNG) images. PNGs are a type raster image file, meaning it stores the individual pixels. I did least significant bit (LSB) steganography, meaning I storing the data in the least significant / last bit of each pixel, making the changes almost impossible to see. I was also inspired to create this after watching a different Computerphile video</p>
<p>I also made this from scratch using zero imports, which allowed me to learn about how exactly the PNG file format actually works</p>

<a href="https://www.youtube.com/watch?v=TWEXCYQKyDc">Steganography Video</a>
