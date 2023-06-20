## AesEncryptDecrypt

### About
It's a shellcode encryptor/decryptor which can be used for bypassing various Antivirus Engines.

### Usage

1. Change the shellcode and key in the AesEncrypt.c
2. Compile the biary using GCC
``` gcc AesEncrypt.c -lbcrypt -o AesEncrypt```
3. Run the AesEncrypt.exe , you will get the Encrypted CipherText
4. For Decryption, change the encrypted shellcode and key , which is obtained from AesEncrypt.exe
5. Use the code, as a part of your malware

### Compatibility
1. 
```
gcc (Rev10, Built by MSYS2 project) 12.2.0
Copyright (C) 2022 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```
2. Use Bcrypt Library while compiling the binary

### Future Works

1. Use of Initialization Vector
2. Full working POC of the malware using this API

### References
1. This API was used by Emotet Malware for encrypting the Shellcode. Ref: https://www.vmray.com/cyber-security-blog/malware-analysis-spotlight-emotets-use-of-cryptography/ 