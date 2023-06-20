# include <stdio.h>
# include <windows.h>
# include <bcrypt.h>
# include <dbghelp.h>
# include <ntstatus.h>

//change the buf and keys, obtained from AesEncrypt
static const BYTE buf[] ={0xd1,0x1f,0x68,0x54,0x0a,0x4f,0x02,0x9a,0xb3,0x36,0xba,0x48,0x4f,0xf0,0xb1,0xda,0x07,0xfe,0x45,0xc1,0xae,0xca,0x32,0x2d,0xad,0xeb,0x2e,0xfc,0xa8,0xef,0x0d,0xe8,0xa1,0x94,0x92,0x93,0x7e,0x28,0x98,0xf8,0x77,0xee,0xf5,0xd9,0x56,0xe6,0xfd,0x0a,0x54,0x7e,0x1a,0xd3,0x6b,0x0a,0x83,0x6c,0xc5,0x11,0x02,0xc0,0xcf,0x45,0x45,0x39,0xdf,0x84,0xf0,0x75,0x78,0x5f,0xb1,0x40,0xfd,0x1d,0x07,0x32,0x7b,0xa6,0x7c,0x88,0x96,0xb0,0x7e,0x56,0xf1,0xd3,0x04,0xa4,0xf1,0xf2,0x31,0x28,0xb3,0x7e,0x7d,0xae,0x80,0xf8,0x3c,0xa8,0x99,0x5b,0x51,0x42,0xc9,0x63,0xb2,0xa0,0x25,0x61,0xdb,0xc3,0xb5,0xda,0x60,0x28,0x36,0xec,0x56,0x90,0x4d,0xd6,0xc8,0x23,0xcf,0xdd,0x29,0xc8,0x6a,0x81,0x51,0xca,0xb9,0x9d,0xcb,0x31,0x7d,0xa5,0x1e,0x84,0xb2,0x7a,0xed,0x7e,0x14,0x09,0x7f,0xb2,0x30,0xe8,0x4e,0xd9,0x0d,0x70,0x72,0xbe,0x1c,0xc3,0xf3,0x0c,0x82,0x5e,0x90,0x95,0x34,0x4a,0xa1,0x2f,0x0b,0x9c,0xc8,0xe1,0x5d,0x66,0x5c,0x93,0xcd,0x87,0xb3,0xd6,0xe4,0x94,0xf0,0x2d,0x35,0x2f,0xba,0x86,0x9b,0x77,0x4b,0x80,0xd3,0x4d,0x38,0xad,0x2f,0x73,0xb2,0x31,0x01,0x38,0x6b,0x01,0xdb,0x85,0xba,0xcd,0xb4,0x7e,0x27,0x1e,0x43,0xaa,0x97,0xa8,0x7a,0xfd,0xe0,0xf9,0xfe,0x8d,0x5b,0x09,0x95,0x6c,0xd9,0xc0,0xae,0x00,0xc7,0x62,0x90,0x28,0x6e,0x05,0xf6,0x9f,0xe1,0xc1,0x7d,0x37,0xf5,0x38,0x60,0x3c,0x07,0x35,0xea,0x54,0xea,0x0a,0xe2,0xe8,0x2b,0x7a,0x31,0x33,0xef,0x60,0x71,0x1e,0xa4,0xb3,0xb8,0x0d,0x99,0xaf,0x1f,0xc2,0xf4,0xaa,0x43,0xa7,0x03,0xf4,0xc8,0x42,0xf4,0x10,0x67,0x04,0x8a,0x39,0xac,0x1a,0x3b,0xf0,0xad,0x3c,0xbf,0x18,0x31,0xdd,0x37,0x47,0x04,0x0f,0xad,0xea,0x3b,0x87,0x4a,0xcf,0xb5,0x08,0xbb,0xed,0x83,0x5f,0xe4,0x74,0xc4,0x8a,0xa7,0x7b,0xb5,0xf6,0x7a,0x54,0xe9,0x03,0x25,0x40,0xfa,0x5b,0x33,0x7b,0x05,0x13,0x68,0x09,0xa9,0x0f,0xfe,0x23};
static const BYTE keyss[]={0x4b,0x44,0x42,0x4d,0x01,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x68,0x65,0x6c,0x6c,0x6f,0x69,0x73,0x73,0x73,0x73,0x73,0x73,0x73,0x73,0x73,0x73};

int main () {


   BCRYPT_ALG_HANDLE phalgorithm;
   LPCWSTR pszAlgId=L"AES";
   LPCWSTR pszImplementation=NULL;
   BCryptOpenAlgorithmProvider(&phalgorithm,BCRYPT_AES_ALGORITHM,NULL,0);
   BCryptSetProperty(phalgorithm,BCRYPT_CHAINING_MODE,(PBYTE)BCRYPT_CHAIN_MODE_CBC,sizeof(BCRYPT_CHAIN_MODE_CBC),0);
   NTSTATUS status;
   BCRYPT_KEY_HANDLE phkey;
   DWORD pboutput;
   ULONG pcbresult;
   if((status=BCryptGetProperty(phalgorithm,BCRYPT_OBJECT_LENGTH,(PUCHAR)&pboutput,sizeof(DWORD),&pcbresult,0)) !=0){
        printf("[+] Error Occured while Getting Key property of Algorithm: %X\n",status);
        exit(0);   
   }
   
   LPVOID heapmemory_key_import=HeapAlloc(GetProcessHeap(),HEAP_GENERATE_EXCEPTIONS,pboutput);
  
   if((status=BCryptImportKey(phalgorithm,NULL,BCRYPT_KEY_DATA_BLOB,&phkey,(PUCHAR)heapmemory_key_import,pboutput,(PUCHAR)keyss,sizeof(keyss),0)) !=0){
        printf("[+] Error Occured while Importing Key: %X\n",status);
        exit(0);   
   }

   
   LPVOID heapmemory_buf=HeapAlloc(GetProcessHeap(),HEAP_GENERATE_EXCEPTIONS,sizeof(buf));
   ULONG decrypted_size;

   if((status=BCryptDecrypt(phkey,(PUCHAR)heapmemory_buf,sizeof(buf),NULL,NULL,0,NULL,0,&decrypted_size,BCRYPT_BLOCK_PADDING)) !=0 ){
        printf("[+] Error: %X\n",status);
        exit(0);       
   }
 
   LPVOID heapmemory_decryptedtext=HeapAlloc(GetProcessHeap(),HEAP_GENERATE_EXCEPTIONS,decrypted_size);
   ULONG pcbresult_decrypt_new;

   if((status=BCryptDecrypt(phkey,(PUCHAR)buf,sizeof(buf),NULL,NULL,0,(PUCHAR)heapmemory_decryptedtext,decrypted_size,&pcbresult_decrypt_new,BCRYPT_BLOCK_PADDING)) !=0) {
        printf("[+] Error: %X\n",status);
        exit(0);       
   }
   
   printf("[+] Printing decrypted text....\n");
   for (DWORD i = 0; i < pcbresult_decrypt_new; i++) {
      printf("0x%02x ", ((PUCHAR)heapmemory_decryptedtext)[i]); 
   }
   
    if(phalgorithm)
    {
        BCryptCloseAlgorithmProvider(phalgorithm,0);
    }

    if (phkey)    
    {
        BCryptDestroyKey(phkey);
    }


    if(heapmemory_decryptedtext)
    {
        HeapFree(GetProcessHeap(), 0, heapmemory_decryptedtext);
    }

    if(heapmemory_buf)
    {
        HeapFree(GetProcessHeap(), 0, heapmemory_buf);
    }

    if(heapmemory_key_import)
    {
        HeapFree(GetProcessHeap(), 0, heapmemory_key_import);
    }
   return 1;

}