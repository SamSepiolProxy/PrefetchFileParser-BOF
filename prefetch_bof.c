#include <windows.h>
#include "beacon.h"

// Kernel32 imports
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapReAlloc(HANDLE, DWORD, LPVOID, SIZE_T);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetFileInformationByHandle(HANDLE, LPBY_HANDLE_FILE_INFORMATION);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FileTimeToLocalFileTime(const FILETIME*, LPFILETIME);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME*, LPSYSTEMTIME);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetVolumeInformationW(LPCWSTR, LPWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPWSTR, DWORD);
DECLSPEC_IMPORT void WINAPI KERNEL32$RtlMoveMemory(PVOID, const VOID*, SIZE_T);

// NTDLL imports
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlDecompressBufferEx(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlGetCompressionWorkSpaceSize(USHORT, PULONG, PULONG);

// MSVCRT imports
DECLSPEC_IMPORT int __cdecl MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT int __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcsrchr(const wchar_t*, wchar_t);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcschr(const wchar_t*, wchar_t);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscpy(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcsncpy(wchar_t*, const wchar_t*, size_t);
DECLSPEC_IMPORT int __cdecl MSVCRT$_snwprintf(wchar_t*, size_t, const wchar_t*, ...);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void*, int, size_t);

// SHLWAPI imports
DECLSPEC_IMPORT LPWSTR WINAPI SHLWAPI$PathFindFileNameW(LPCWSTR);
DECLSPEC_IMPORT LPWSTR WINAPI SHLWAPI$StrChrW(LPCWSTR, WCHAR);
DECLSPEC_IMPORT int WINAPI SHLWAPI$StrCmpIW(LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT LPWSTR WINAPI SHLWAPI$StrRChrW(LPCWSTR, LPCWSTR, WCHAR);

// Constants
#define PREFETCH_SIGNATURE              0x41434353
#define PREFETCH_COMPRESSED_SIGNATURE   0x044D414D
#define PREFETCH_VERSION_WIN10          30
#define PREFETCH_VERSION_WIN11          31
#define PREFETCH_MAX_LAST_RUN_TIMES     8
#define PREFETCH_PATH                   L"C:\\Windows\\Prefetch"
#define DRIVE_LETTER_COUNT              26
#define ARRAY_INITIAL_CAPACITY          64
#define MAX_BINARY_FILTERS              64

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#pragma pack(push, 1)
typedef struct _PREFETCH_MAM_HEADER {
    DWORD dwSignature;
    DWORD dwUncompressedSize;
} PREFETCH_MAM_HEADER, *PPREFETCH_MAM_HEADER;

typedef struct _PREFETCH_HEADER {
    DWORD dwVersion;
    DWORD dwSignature;
    DWORD dwUnknown1;
    DWORD dwFileSize;
    WCHAR wszExecutableName[30];
    DWORD dwHash;
    DWORD dwUnknown2;
} PREFETCH_HEADER, *PPREFETCH_HEADER;

typedef struct _PREFETCH_FILE_INFO {
    DWORD dwMetricsArrayOffset;
    DWORD dwMetricsArrayCount;
    DWORD dwTraceChainsOffset;
    DWORD dwTraceChainsCount;
    DWORD dwFilenameStringsOffset;
    DWORD dwFilenameStringsSize;
    DWORD dwVolumesInfoOffset;
    DWORD dwVolumesInfoCount;
    DWORD dwVolumesInfoSize;
    DWORD dwTotalDirectoryCount;
    DWORD dwUnknown1;
    FILETIME ftLastRunTime[8];
} PREFETCH_FILE_INFO, *PPREFETCH_FILE_INFO;

typedef struct _PREFETCH_VOLUME_INFO {
    DWORD dwDevicePathOffset;
    DWORD dwDevicePathLength;
    FILETIME ftCreationTime;
    DWORD dwSerialNumber;
    DWORD dwFileReferencesOffset;
    DWORD dwFileReferencesSize;
    DWORD dwDirectoryStringsOffset;
    DWORD dwDirectoryStringsCount;
    BYTE padding[64];
} PREFETCH_VOLUME_INFO, *PPREFETCH_VOLUME_INFO;
#pragma pack(pop)

#define PREFETCH_RUN_COUNT_OFFSET_V30_1 0x74
#define PREFETCH_RUN_COUNT_OFFSET_V30_2 0x70

typedef struct _PREFETCH_ENTRY {
    WCHAR wszExecutableName[64];
    WCHAR wszPrefetchFile[260];
    DWORD dwRunCount;
    FILETIME ftLastRunTimes[PREFETCH_MAX_LAST_RUN_TIMES];
    DWORD dwLastRunTimeCount;
    DWORD dwVersion;
    DWORD dwHash;
    WCHAR wszExecutablePath[260];
    LPWSTR* ppszLoadedFiles;
    DWORD dwLoadedFileCount;
    LPWSTR* ppszDirectories;
    DWORD dwDirectoryCount;
    FILETIME ftPrefetchCreated;
    FILETIME ftPrefetchModified;
} PREFETCH_ENTRY, *PPREFETCH_ENTRY;

typedef struct _PREFETCH_LIST {
    DWORD dwCount;
    DWORD dwCapacity;
    PPREFETCH_ENTRY pEntries;
} PREFETCH_LIST, *PPREFETCH_LIST;

// Global filter variables
WCHAR g_szBinaryFilters[MAX_BINARY_FILTERS][260];
DWORD g_dwBinaryFilterCount = 0;

// Helper functions
static BOOL PrefetchListInit(PPREFETCH_LIST pList, DWORD dwInitialCapacity) {
    if (!pList || dwInitialCapacity == 0) return FALSE;
    
    MSVCRT$memset(pList, 0, sizeof(PREFETCH_LIST));
    
    pList->pEntries = (PPREFETCH_ENTRY)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 
                                                           dwInitialCapacity * sizeof(PREFETCH_ENTRY));
    if (!pList->pEntries)
        return FALSE;
    
    pList->dwCapacity = dwInitialCapacity;
    return TRUE;
}

static VOID PrefetchListFree(PPREFETCH_LIST pList) {
    if (!pList) return;
    
    if (pList->pEntries) {
        for (DWORD i = 0; i < pList->dwCount; i++) {
            PPREFETCH_ENTRY pEntry = &pList->pEntries[i];
            
            if (pEntry->ppszLoadedFiles) {
                for (DWORD j = 0; j < pEntry->dwLoadedFileCount; j++) {
                    if (pEntry->ppszLoadedFiles[j])
                        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pEntry->ppszLoadedFiles[j]);
                }
                KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pEntry->ppszLoadedFiles);
            }
            
            if (pEntry->ppszDirectories) {
                for (DWORD j = 0; j < pEntry->dwDirectoryCount; j++) {
                    if (pEntry->ppszDirectories[j])
                        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pEntry->ppszDirectories[j]);
                }
                KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pEntry->ppszDirectories);
            }
        }
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pList->pEntries);
    }
    
    MSVCRT$memset(pList, 0, sizeof(PREFETCH_LIST));
}

static BOOL PrefetchListExpand(PPREFETCH_LIST pList) {
    if (!pList) return FALSE;
    
    DWORD dwNewCapacity = pList->dwCapacity * 2;
    PPREFETCH_ENTRY pNewEntry = (PPREFETCH_ENTRY)KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), 
                                                                       HEAP_ZERO_MEMORY, 
                                                                       pList->pEntries, 
                                                                       dwNewCapacity * sizeof(PREFETCH_ENTRY));
    if (!pNewEntry)
        return FALSE;
    
    pList->pEntries = pNewEntry;
    pList->dwCapacity = dwNewCapacity;
    return TRUE;
}

static PPREFETCH_ENTRY PrefetchListAdd(PPREFETCH_LIST pList) {
    if (!pList) return NULL;
    
    if (pList->dwCount >= pList->dwCapacity) {
        if (!PrefetchListExpand(pList))
            return NULL;
    }
    
    return &pList->pEntries[pList->dwCount++];
}

static PBYTE DecompressPrefetch(PBYTE pbCompressed, DWORD dwCompressedSize, PDWORD pdwDecompressedSize) {
    PPREFETCH_MAM_HEADER pMamHeader = NULL;
    PBYTE pbDecompressed = NULL;
    PBYTE pbWorkSpace = NULL;
    ULONG ulWorkSpaceSize = 0;
    ULONG ulFinalSize = 0;
    ULONG ulTemp = 0;
    NTSTATUS ntStatus = 0;
    
    if (!pbCompressed || !pdwDecompressedSize || dwCompressedSize < sizeof(PREFETCH_MAM_HEADER))
        return NULL;
    
    *pdwDecompressedSize = 0;
    pMamHeader = (PPREFETCH_MAM_HEADER)pbCompressed;
    
    if (pMamHeader->dwSignature != PREFETCH_COMPRESSED_SIGNATURE)
        return NULL;
    
    ntStatus = NTDLL$RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS_HUFF | COMPRESSION_ENGINE_MAXIMUM, 
                                                     &ulWorkSpaceSize, &ulTemp);
    if (!NT_SUCCESS(ntStatus))
        return NULL;
    
    pbWorkSpace = (PBYTE)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, ulWorkSpaceSize);
    if (!pbWorkSpace)
        return NULL;
    
    pbDecompressed = (PBYTE)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, pMamHeader->dwUncompressedSize);
    if (!pbDecompressed) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pbWorkSpace);
        return NULL;
    }
    
    ntStatus = NTDLL$RtlDecompressBufferEx(COMPRESSION_FORMAT_XPRESS_HUFF, 
                                           pbDecompressed, 
                                           pMamHeader->dwUncompressedSize,
                                           pbCompressed + sizeof(PREFETCH_MAM_HEADER), 
                                           dwCompressedSize - sizeof(PREFETCH_MAM_HEADER),
                                           &ulFinalSize, 
                                           pbWorkSpace);
    
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pbWorkSpace);
    
    if (!NT_SUCCESS(ntStatus)) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pbDecompressed);
        return NULL;
    }
    
    *pdwDecompressedSize = ulFinalSize;
    return pbDecompressed;
}

// Simplified parsing - extract key information only
static BOOL ParsePrefetchData(PBYTE pbData, DWORD dwDataSize, PPREFETCH_ENTRY pEntry) {
    PPREFETCH_HEADER pHeader = NULL;
    PPREFETCH_FILE_INFO pInfo = NULL;
    
    if (!pbData || !pEntry || dwDataSize < sizeof(PREFETCH_HEADER))
        return FALSE;
    
    pHeader = (PPREFETCH_HEADER)pbData;
    
    if (pHeader->dwSignature != PREFETCH_SIGNATURE)
        return FALSE;
    
    if (pHeader->dwVersion != PREFETCH_VERSION_WIN10 && pHeader->dwVersion != PREFETCH_VERSION_WIN11)
        return FALSE;
    
    // Copy basic info
    MSVCRT$wcsncpy(pEntry->wszExecutableName, pHeader->wszExecutableName, 63);
    pEntry->wszExecutableName[63] = L'\0';
    pEntry->dwVersion = pHeader->dwVersion;
    pEntry->dwHash = pHeader->dwHash;
    
    // Get file info structure
    if (dwDataSize < sizeof(PREFETCH_HEADER) + sizeof(PREFETCH_FILE_INFO))
        return FALSE;
    
    pInfo = (PPREFETCH_FILE_INFO)(pbData + sizeof(PREFETCH_HEADER));
    
    // Extract last run times
    pEntry->dwLastRunTimeCount = 0;
    for (DWORD i = 0; i < PREFETCH_MAX_LAST_RUN_TIMES; i++) {
        if (pInfo->ftLastRunTime[i].dwHighDateTime != 0 || pInfo->ftLastRunTime[i].dwLowDateTime != 0) {
            MSVCRT$memcpy(&pEntry->ftLastRunTimes[i], &pInfo->ftLastRunTime[i], sizeof(FILETIME));
            pEntry->dwLastRunTimeCount++;
        }
    }
    
    // Get run count based on version
    DWORD dwRunCountOffset = (pHeader->dwVersion == PREFETCH_VERSION_WIN11 || 
                              dwDataSize < 220) ? PREFETCH_RUN_COUNT_OFFSET_V30_2 : PREFETCH_RUN_COUNT_OFFSET_V30_1;
    
    if (sizeof(PREFETCH_HEADER) + dwRunCountOffset + sizeof(DWORD) <= dwDataSize) {
        MSVCRT$memcpy(&pEntry->dwRunCount, pbData + sizeof(PREFETCH_HEADER) + dwRunCountOffset, sizeof(DWORD));
    }
    
    return TRUE;
}

static BOOL ShouldProcessFile(LPCWSTR pszFileName, LPCWSTR pszExecutableName) {
    if (g_dwBinaryFilterCount == 0)
        return TRUE;
    
    // Match against the executable name if we have it
    if (pszExecutableName && pszExecutableName[0] != L'\0') {
        for (DWORD i = 0; i < g_dwBinaryFilterCount; i++) {
            if (SHLWAPI$StrCmpIW(pszExecutableName, g_szBinaryFilters[i]) == 0)
                return TRUE;
        }
    }
    
    // Fallback: try to extract executable name from prefetch filename
    // Format is typically: EXECUTABLE.EXE-HASH.pf
    WCHAR szExeName[260] = {0};
    WCHAR* pDash = SHLWAPI$StrChrW(pszFileName, L'-');
    
    if (pDash) {
        // Copy everything before the dash
        int len = (int)(pDash - pszFileName);
        if (len > 0 && len < 260) {
            MSVCRT$wcsncpy(szExeName, pszFileName, len);
            szExeName[len] = L'\0';
            
            for (DWORD i = 0; i < g_dwBinaryFilterCount; i++) {
                if (SHLWAPI$StrCmpIW(szExeName, g_szBinaryFilters[i]) == 0)
                    return TRUE;
            }
        }
    }
    
    return FALSE;
}

static BOOL ParsePrefetchFile(LPCWSTR pszFilePath, PPREFETCH_ENTRY pEntry) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PBYTE pbFileData = NULL;
    PBYTE pbParsedData = NULL;
    DWORD dwFileSize = 0;
    DWORD dwBytesRead = 0;
    DWORD dwParsedSize = 0;
    BOOL bCompressed = FALSE;
    BOOL bResult = FALSE;
    BY_HANDLE_FILE_INFORMATION FileInformation = {0};
    PPREFETCH_MAM_HEADER pMamHeader = NULL;
    
    hFile = KERNEL32$CreateFileW(pszFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    dwFileSize = KERNEL32$GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE || dwFileSize == 0) {
        goto _END_OF_FUNC;
    }
    
    pbFileData = (PBYTE)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, dwFileSize);
    if (!pbFileData) {
        goto _END_OF_FUNC;
    }
    
    if (!KERNEL32$ReadFile(hFile, pbFileData, dwFileSize, &dwBytesRead, NULL) || dwBytesRead != dwFileSize) {
        goto _END_OF_FUNC;
    }
    
    if (KERNEL32$GetFileInformationByHandle(hFile, &FileInformation)) {
        pEntry->ftPrefetchCreated = FileInformation.ftCreationTime;
        pEntry->ftPrefetchModified = FileInformation.ftLastWriteTime;
    }
    
    // Check if compressed
    if (dwFileSize >= sizeof(PREFETCH_MAM_HEADER)) {
        pMamHeader = (PPREFETCH_MAM_HEADER)pbFileData;
        
        if (pMamHeader->dwSignature == PREFETCH_COMPRESSED_SIGNATURE) {
            bCompressed = TRUE;
            pbParsedData = DecompressPrefetch(pbFileData, dwFileSize, &dwParsedSize);
            if (!pbParsedData)
                goto _END_OF_FUNC;
        }
    }
    
    if (!bCompressed) {
        pbParsedData = pbFileData;
        dwParsedSize = dwFileSize;
        pbFileData = NULL;
    }
    
    if (!ParsePrefetchData(pbParsedData, dwParsedSize, pEntry))
        goto _END_OF_FUNC;
    
    MSVCRT$wcscpy(pEntry->wszPrefetchFile, SHLWAPI$PathFindFileNameW(pszFilePath));
    bResult = TRUE;
    
_END_OF_FUNC:
    if (hFile != INVALID_HANDLE_VALUE)
        KERNEL32$CloseHandle(hFile);
    if (pbFileData)
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pbFileData);
    if (bCompressed && pbParsedData)
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pbParsedData);
    return bResult;
}

static BOOL EnumeratePrefetch(PPREFETCH_LIST pList, LPCWSTR pszPrefetchPath) {
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW FindData = {0};
    PPREFETCH_ENTRY pEntry = NULL;
    WCHAR szSearchPath[260] = {0};
    WCHAR szFilePath[260] = {0};
    BOOL bResult = FALSE;
    
    if (!pList) return FALSE;
    
    if (!PrefetchListInit(pList, ARRAY_INITIAL_CAPACITY))
        goto _END_OF_FUNC;
    
    MSVCRT$_snwprintf(szSearchPath, 259, L"%s\\*.pf", pszPrefetchPath);
    
    hFind = KERNEL32$FindFirstFileW(szSearchPath, &FindData);
    if (hFind == INVALID_HANDLE_VALUE) {
        goto _END_OF_FUNC;
    }
    
    do {
        if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        
        MSVCRT$_snwprintf(szFilePath, 259, L"%s\\%s", pszPrefetchPath, FindData.cFileName);
        
        pEntry = PrefetchListAdd(pList);
        if (!pEntry)
            continue;
        
        if (!ParsePrefetchFile(szFilePath, pEntry)) {
            pList->dwCount--;
            MSVCRT$memset(pEntry, 0, sizeof(PREFETCH_ENTRY));
            continue;
        }
        
        // Check filter after parsing so we have the executable name
        if (!ShouldProcessFile(FindData.cFileName, pEntry->wszExecutableName)) {
            pList->dwCount--;
            MSVCRT$memset(pEntry, 0, sizeof(PREFETCH_ENTRY));
            continue;
        }
        
    } while (KERNEL32$FindNextFileW(hFind, &FindData));
    
    bResult = TRUE;
    
_END_OF_FUNC:
    if (hFind != INVALID_HANDLE_VALUE)
        KERNEL32$FindClose(hFind);
    return bResult;
}

static VOID FormatFileTime(PFILETIME pFileTime, LPWSTR pszBuffer, DWORD dwBufferSize) {
    SYSTEMTIME SystemTime = {0};
    FILETIME ftLocal = {0};
    
    if (!pFileTime || !pszBuffer || dwBufferSize == 0)
        return;
    
    if (pFileTime->dwHighDateTime == 0 && pFileTime->dwLowDateTime == 0) {
        MSVCRT$wcscpy(pszBuffer, L"N/A");
        return;
    }
    
    KERNEL32$FileTimeToLocalFileTime(pFileTime, &ftLocal);
    KERNEL32$FileTimeToSystemTime(&ftLocal, &SystemTime);
    
    MSVCRT$_snwprintf(pszBuffer, dwBufferSize - 1, L"%04d-%02d-%02d %02d:%02d:%02d",
        SystemTime.wYear, SystemTime.wMonth, SystemTime.wDay, 
        SystemTime.wHour, SystemTime.wMinute, SystemTime.wSecond);
}

static VOID OutputPrefetchList(PPREFETCH_LIST pList) {
    WCHAR szTime[64] = {0};
    
    if (!pList) return;
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n========== Prefetch Analysis ==========\n");
    BeaconPrintf(CALLBACK_OUTPUT, "Total Entries: %lu\n\n", pList->dwCount);
    
    for (DWORD i = 0; i < pList->dwCount; i++) {
        PPREFETCH_ENTRY pEntry = &pList->pEntries[i];
        
        BeaconPrintf(CALLBACK_OUTPUT, "[%lu] %ls\n", i + 1, pEntry->wszExecutableName);
        BeaconPrintf(CALLBACK_OUTPUT, "  Prefetch File: %ls\n", pEntry->wszPrefetchFile);
        BeaconPrintf(CALLBACK_OUTPUT, "  Hash: %08X\n", pEntry->dwHash);
        BeaconPrintf(CALLBACK_OUTPUT, "  Run Count: %lu\n", pEntry->dwRunCount);
        BeaconPrintf(CALLBACK_OUTPUT, "  Version: %lu\n", pEntry->dwVersion);
        
        FormatFileTime(&pEntry->ftPrefetchCreated, szTime, 64);
        BeaconPrintf(CALLBACK_OUTPUT, "  Created: %ls\n", szTime);
        
        FormatFileTime(&pEntry->ftPrefetchModified, szTime, 64);
        BeaconPrintf(CALLBACK_OUTPUT, "  Modified: %ls\n", szTime);
        
        if (pEntry->dwLastRunTimeCount > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "  Last Run Times:\n");
            for (DWORD j = 0; j < pEntry->dwLastRunTimeCount; j++) {
                FormatFileTime(&pEntry->ftLastRunTimes[j], szTime, 64);
                BeaconPrintf(CALLBACK_OUTPUT, "    [%lu] %ls\n", j + 1, szTime);
            }
        }
        
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }
}

void go(char *args, int len) {
    datap parser;
    char *szPrefetchPath = NULL;
    char *szFilter = NULL;
    WCHAR wszPrefetchPath[260] = PREFETCH_PATH;
    PREFETCH_LIST PrefetchList = {0};
    int filterLen = 0;
    
    BeaconDataParse(&parser, args, len);
    szPrefetchPath = BeaconDataExtract(&parser, NULL);
    
    // Convert prefetch path if provided
    if (szPrefetchPath && szPrefetchPath[0] != '\0') {
        // Convert ASCII to wide char
        for (int i = 0; i < 259 && szPrefetchPath[i]; i++) {
            wszPrefetchPath[i] = (WCHAR)szPrefetchPath[i];
        }
        wszPrefetchPath[259] = L'\0';
    }
    
    // Parse optional filters
    while (BeaconDataLength(&parser) > 0) {
        szFilter = BeaconDataExtract(&parser, &filterLen);
        if (szFilter && g_dwBinaryFilterCount < MAX_BINARY_FILTERS) {
            // Convert ASCII to wide char
            for (int i = 0; i < 259 && i < filterLen && szFilter[i]; i++) {
                g_szBinaryFilters[g_dwBinaryFilterCount][i] = (WCHAR)szFilter[i];
            }
            g_szBinaryFilters[g_dwBinaryFilterCount][259] = L'\0';
            g_dwBinaryFilterCount++;
        }
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Parsing prefetch from: %ls\n", wszPrefetchPath);
    
    if (g_dwBinaryFilterCount > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Filters: %lu\n", g_dwBinaryFilterCount);
    }
    
    if (!EnumeratePrefetch(&PrefetchList, wszPrefetchPath)) {
        PrefetchListFree(&PrefetchList);
        return;
    }
    
    if (PrefetchList.dwCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] No entries found\n");
        PrefetchListFree(&PrefetchList);
        return;
    }
    
    OutputPrefetchList(&PrefetchList);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Parsed %lu entries\n", PrefetchList.dwCount);
    
    PrefetchListFree(&PrefetchList);
}
