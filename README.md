# SADcipher
A POC file encryptor that uses xor keys to cipher files in a directory.<br>
It can encrypt 100 files in under 3-4 seconds.

## How do I decrypt the files?

Here is a small poc code I wrote for the decryption process:
```cpp
FILE* stream = fopen(fName, "rb");
DWORD size   = 0;//your file size, can be easily found using winAPI functions
void* buffer = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 

DWORD extension      = header->extension ^ header->INT_KEY;
DWORD originalSize   = header->originalSize ^ header->INT_KEY;
DWORD first_key      = header->XOR_KEY ^ header->INT_KEY;
DWORD second_key     = header->ENC_KEY ^ header->INT_KEY;
void* OriginalBuffer = (BYTE*)buffer+sizeof(SAD_HEADER);

for(int i = 0;i < originalSize/4;i++){
  DWORD* sec = (DWORD*)OriginalBuffer+i;
  if(*sec == 0x00000000)
    continue;
  else {
    *sec ^= first_key;
    *sec ^= second_key;
  }
}
VirtualFree(buffer, 0, MEM_RELEASE);
```
## Credits
AlexSimpler 2020
All rights reserved
