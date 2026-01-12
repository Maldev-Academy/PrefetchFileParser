#include "Headers.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Global Variables

WCHAR   g_szOutputPath[MAX_PATH]                            = DEFAULT_OUTPUT_FILENAME;
WCHAR   g_szPrefetchPath[MAX_PATH]                          = PREFETCH_PATH;
WCHAR   g_szBinaryFilters[MAX_BINARY_FILTERS][MAX_PATH]     = { 0 };
DWORD   g_dwBinaryFilterCount                               = 0x00;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Dynamic List Functions

static BOOL PrefetchListInit(IN OUT PPREFETCH_LIST pList, IN DWORD dwInitialCapacity)
{
    if (!pList || dwInitialCapacity == 0) return FALSE;

    RtlSecureZeroMemory(pList, sizeof(PREFETCH_LIST));

    if (!(pList->pEntries = (PPREFETCH_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwInitialCapacity * sizeof(PREFETCH_ENTRY))))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    pList->dwCapacity = dwInitialCapacity;
    return TRUE;
}

static VOID PrefetchListFree(IN OUT PPREFETCH_LIST pList)
{
    if (!pList) return;

    if (pList->pEntries)
    {
        for (DWORD i = 0; i < pList->dwCount; i++)
        {
            PPREFETCH_ENTRY pEntry = &pList->pEntries[i];

            // Free loaded files array
            if (pEntry->ppszLoadedFiles)
            {
                for (DWORD j = 0; j < pEntry->dwLoadedFileCount; j++)
                {
                    if (pEntry->ppszLoadedFiles[j])
                        HeapFree(GetProcessHeap(), 0, pEntry->ppszLoadedFiles[j]);
                }
                HeapFree(GetProcessHeap(), 0, pEntry->ppszLoadedFiles);
            }

            // Free directories array
            if (pEntry->ppszDirectories)
            {
                for (DWORD j = 0; j < pEntry->dwDirectoryCount; j++)
                {
#pragma warning(suppress: 6001)
                    if (pEntry->ppszDirectories[j])
                        HeapFree(GetProcessHeap(), 0, pEntry->ppszDirectories[j]);
                }
#pragma warning(suppress: 6001)
                HeapFree(GetProcessHeap(), 0, pEntry->ppszDirectories);
            }
        }

        HeapFree(GetProcessHeap(), 0, pList->pEntries);
    }

    RtlSecureZeroMemory(pList, sizeof(PREFETCH_LIST));
}

static BOOL PrefetchListExpand(IN OUT PPREFETCH_LIST pList)
{
    PPREFETCH_ENTRY pNewEntry        = NULL;
    DWORD           dwNewCapacity    = 0x00;

    if (!pList) return FALSE;

#define GROWTH_FACTOR 2

    dwNewCapacity = pList->dwCapacity * GROWTH_FACTOR;

#undef GROWTH_FACTOR

    if (!(pNewEntry = (PPREFETCH_ENTRY)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pList->pEntries, dwNewCapacity * sizeof(PREFETCH_ENTRY))))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    pList->pEntries     = pNewEntry;
    pList->dwCapacity   = dwNewCapacity;

    return TRUE;
}

static PPREFETCH_ENTRY PrefetchListAdd(IN OUT PPREFETCH_LIST pList)
{
    if (!pList) return NULL;

    if (pList->dwCount >= pList->dwCapacity)
    {
        if (!PrefetchListExpand(pList))
            return NULL;
    }

    return &pList->pEntries[pList->dwCount++];
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Decompression Functions

static PBYTE DecompressPrefetch(IN PBYTE pbCompressed, IN DWORD dwCompressedSize, OUT PDWORD pdwDecompressedSize)
{
    PPREFETCH_MAM_HEADER    pMamHeader          = NULL;
    PBYTE                   pbDecompressed      = NULL,
                            pbWorkSpace         = NULL;
    ULONG                   ulWorkSpaceSize     = 0UL,
                            ulFinalSize         = 0UL;
    NTSTATUS                ntSTATUS            = 0x00;

    if (!pbCompressed || !pdwDecompressedSize || dwCompressedSize < sizeof(PREFETCH_MAM_HEADER)) return NULL;

    *pdwDecompressedSize    = 0x00;
    pMamHeader              = (PPREFETCH_MAM_HEADER)pbCompressed;

    if (pMamHeader->dwSignature != PREFETCH_COMPRESSED_SIGNATURE)
    {
        printf("[!] Prefetch MAM Header Signature Mismatch. Got 0x%0.8X Instead Of 0x%0.8X \n", pMamHeader->dwSignature, PREFETCH_COMPRESSED_SIGNATURE);
        return NULL;
    }

    if (!NT_SUCCESS(ntSTATUS = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS_HUFF | COMPRESSION_ENGINE_MAXIMUM, &ulWorkSpaceSize, &ulFinalSize)))
    {
        printf("[!] RtlGetCompressionWorkSpaceSize Failed With Error: 0x%08X\n", ntSTATUS);
        goto _END_OF_FUNC;
    }

    if (!(pbWorkSpace = (PBYTE)HeapAlloc(GetProcessHeap(), 0, ulWorkSpaceSize)))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(pbDecompressed = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pMamHeader->dwUncompressedSize)))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!NT_SUCCESS(ntSTATUS = RtlDecompressBufferEx(COMPRESSION_FORMAT_XPRESS_HUFF, pbDecompressed, pMamHeader->dwUncompressedSize, pbCompressed + sizeof(PREFETCH_MAM_HEADER), dwCompressedSize - sizeof(PREFETCH_MAM_HEADER), &ulFinalSize, pbWorkSpace)))
    {
        printf("[!] RtlDecompressBufferEx Failed With Error: 0x%08X\n", ntSTATUS);
        goto _END_OF_FUNC;
    }

    *pdwDecompressedSize = ulFinalSize;

_END_OF_FUNC:
    if (pbWorkSpace)
        HeapFree(GetProcessHeap(), 0, pbWorkSpace);
    if (!*pdwDecompressedSize && pbDecompressed)
    {
        HeapFree(GetProcessHeap(), 0, pbDecompressed);
        pbDecompressed = NULL;
    }
    return pbDecompressed;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Extraction Functions

static BOOL ExtractFilenameStrings(IN PBYTE pbData, IN DWORD dwDataSize, IN PPREFETCH_HEADER pHeader, IN PPREFETCH_FILE_INFO pInfo, OUT PPREFETCH_ENTRY pEntry)
{
    DWORD   dwOffset            = pInfo->dwFilenameStringsOffset,
            dwEndOffset         = dwOffset + pInfo->dwFilenameStringsSize,
            dwPosition          = 0x00,
            dwCount             = 0x00,
            dwLength            = 0x00,
            dwExeNameLength     = 0x00;
    LPWSTR* ppszTemp            = NULL;
    LPWSTR  pszCurrent          = NULL,
            pszFileName         = NULL;
    SIZE_T  cbLength            = 0x00;
    HRESULT hResult             = S_OK;
    BOOL    bResult             = FALSE;

    if (dwEndOffset > dwDataSize) return FALSE;

    // Count strings first
    dwPosition = dwOffset;
    
    while (dwPosition < dwEndOffset)
    {
        pszCurrent = (LPWSTR)(pbData + dwPosition);
        
        if (FAILED(StringCchLengthW(pszCurrent, (dwEndOffset - dwPosition) / sizeof(WCHAR), &cbLength)) || cbLength == 0)
            break;
        
        dwCount++;
        dwPosition += ((DWORD)cbLength + 1) * sizeof(WCHAR);
    }

    if (dwCount == 0x00) return TRUE;

    if (!(ppszTemp = (LPWSTR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCount * sizeof(LPWSTR))))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    dwPosition = dwOffset;
    
    if (FAILED((hResult = StringCchLengthW(pHeader->wszExecutableName, MAX_PATH, &cbLength))))
    {
        printf("[!] StringCchLengthW Failed With Error: 0x%0.8X\n", hResult);
        goto _END_OF_FUNC;
    }
    
    dwExeNameLength = (DWORD)cbLength;

    for (DWORD i = 0; i < dwCount && dwPosition < dwEndOffset; i++)
    {
        pszCurrent = (LPWSTR)(pbData + dwPosition);
        
        if (FAILED(StringCchLengthW(pszCurrent, (dwEndOffset - dwPosition) / sizeof(WCHAR), &cbLength)) || cbLength == 0)
            break;

        dwLength = (DWORD)cbLength;

        // Check if this is the executable (filename matches header name)
        if (pEntry->wszExecutablePath[0] == L'\0' && dwLength >= dwExeNameLength)
        {
            if ((pszFileName = StrRChrW(pszCurrent, NULL, L'\\')) && StrCmpIW(++pszFileName, pHeader->wszExecutableName) == 0)
                StringCchCopyW(pEntry->wszExecutablePath, MAX_PATH, pszCurrent);
        }

        // Allocate and copy string
        if ((ppszTemp[i] = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, (dwLength + 1) * sizeof(WCHAR))))
            StringCchCopyW(ppszTemp[i], dwLength + 1, pszCurrent);

        dwPosition += (dwLength + 1) * sizeof(WCHAR);
    }

    pEntry->ppszLoadedFiles     = ppszTemp;
    pEntry->dwLoadedFileCount   = dwCount;
    bResult                     = TRUE;

_END_OF_FUNC:
    if (!bResult && ppszTemp)
    {
        for (DWORD i = 0; i < dwCount; i++)
        {
            if (ppszTemp[i]) HeapFree(GetProcessHeap(), 0, ppszTemp[i]);
        }
        HeapFree(GetProcessHeap(), 0, ppszTemp);
    }
    return bResult;
}

static BOOL ExtractVolumeInfo(IN PBYTE pbData, IN DWORD dwDataSize, IN PPREFETCH_FILE_INFO pInfo, OUT PPREFETCH_ENTRY pEntry)
{
    PPREFETCH_VOLUME_INFO   pVolumeInfo         = NULL;
    LPWSTR                  pszDevicePath       = NULL;
    DWORD                   dwOffset            = pInfo->dwVolumesInfoOffset,
                            dwPathOffset        = 0;

    if (pInfo->dwVolumesInfoCount == 0x00) return TRUE;

    if (dwOffset + sizeof(PREFETCH_VOLUME_INFO) > dwDataSize) return FALSE;

    pVolumeInfo     = (PPREFETCH_VOLUME_INFO)(pbData + dwOffset);
    dwPathOffset    = dwOffset + pVolumeInfo->dwDevicePathOffset;

    // Extract device path
    if (dwPathOffset + pVolumeInfo->dwDevicePathLength * sizeof(WCHAR) <= dwDataSize)
    {
        pszDevicePath = (LPWSTR)(pbData + dwPathOffset);
        StringCchCopyNW(pEntry->wszVolumeDevicePath, MAX_PATH, pszDevicePath, pVolumeInfo->dwDevicePathLength);
    }

    pEntry->dwVolumeSerialNumber    = pVolumeInfo->dwSerialNumber;
    pEntry->ftVolumeCreationTime    = pVolumeInfo->ftCreationTime;

    return TRUE;
}

static BOOL ExtractDirectoryStrings(IN PBYTE pbData, IN DWORD dwDataSize, IN PPREFETCH_FILE_INFO pInfo, OUT PPREFETCH_ENTRY pEntry)
{
    PPREFETCH_VOLUME_INFO   pVolumeInfo             = NULL;
    LPWSTR*                 ppszDirectories         = NULL;
    LPWSTR                  pszDirectory            = NULL;
    DWORD                   dwVolumeOffset          = pInfo->dwVolumesInfoOffset,
                            dwDirectoryOffset       = 0x00,
                            dwDirectoryCount        = 0x00,
                            dwPosition              = 0x00;
    WORD                    wLength                 = 0x00;
    BOOL                    bResult                 = FALSE;

    if (pInfo->dwVolumesInfoCount == 0x00) return TRUE;

    if (dwVolumeOffset + sizeof(PREFETCH_VOLUME_INFO) > dwDataSize) return FALSE;

    pVolumeInfo         = (PPREFETCH_VOLUME_INFO)(pbData + dwVolumeOffset);
    dwDirectoryOffset   = dwVolumeOffset + pVolumeInfo->dwDirectoryStringsOffset;
    dwDirectoryCount    = pVolumeInfo->dwDirectoryStringsCount;

    if (dwDirectoryCount == 0x00) return TRUE;

    if (!(ppszDirectories = (LPWSTR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDirectoryCount * sizeof(LPWSTR))))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    dwPosition = dwDirectoryOffset;
    for (DWORD i = 0; i < dwDirectoryCount && dwPosition < dwDataSize; i++)
    {
        // Directory strings are prefixed with 2-byte length (in characters, not including null)
        if (dwPosition + sizeof(WORD) > dwDataSize)
            break;

        wLength     = *(WORD*)(pbData + dwPosition);
        dwPosition  += sizeof(WORD);

        if (dwPosition + (wLength + 1) * sizeof(WCHAR) > dwDataSize)
            break;

        pszDirectory = (LPWSTR)(pbData + dwPosition);

        if ((ppszDirectories[i] = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, (wLength + 2) * sizeof(WCHAR))))
            StringCchCopyNW(ppszDirectories[i], wLength + 2, pszDirectory, wLength + 1);

        dwPosition += (wLength + 1) * sizeof(WCHAR);
    }

    pEntry->ppszDirectories     = ppszDirectories;
    pEntry->dwDirectoryCount    = dwDirectoryCount;
    bResult                     = TRUE;

_END_OF_FUNC:
    if (!bResult && ppszDirectories)
    {
        for (DWORD i = 0; i < dwDirectoryCount; i++)
        {
            if (ppszDirectories[i]) HeapFree(GetProcessHeap(), 0, ppszDirectories[i]);
        }
        HeapFree(GetProcessHeap(), 0, ppszDirectories);
    }
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Filter Logic

static BOOL ShouldProcessFile(IN PCWSTR pszFileName)
{
    WCHAR   szBaseName[MAX_PATH]    = { 0 };
    PCWSTR  pszDash                 = NULL;

    if (g_dwBinaryFilterCount == 0x00) return TRUE;

    // Extract base name (before the dash and hash)
    StringCchCopyW(szBaseName, MAX_PATH, pszFileName);

    if ((pszDash = StrChrW(szBaseName, L'-')))
        szBaseName[pszDash - szBaseName] = L'\0';

    for (DWORD i = 0; i < g_dwBinaryFilterCount; i++)
    {
        if (StrCmpIW(szBaseName, g_szBinaryFilters[i]) == 0)
            return TRUE;
    }

    return FALSE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Prefetch Enumeration & Parsing

static BOOL ParsePrefetchData(IN PBYTE pbData, IN DWORD dwDataSize, OUT PPREFETCH_ENTRY pEntry)
{
    PPREFETCH_HEADER        pHeader             = NULL;
    PPREFETCH_FILE_INFO     pFileInfo           = NULL;
    DWORD                   dwRunCountOffset    = 0x00,
                            dwRunCount          = 0x00,
                            dwFileInfoSize      = 0x00;
    BOOL                    bResult             = FALSE;

    if (!pbData || !pEntry || dwDataSize < sizeof(PREFETCH_HEADER)) return FALSE;

    pHeader = (PPREFETCH_HEADER)pbData;

    if (pHeader->dwSignature != PREFETCH_SIGNATURE) return FALSE;

    switch (pHeader->dwVersion)
    {
        case PREFETCH_VERSION_WIN10:
        case PREFETCH_VERSION_WIN11:
        {
            if (dwDataSize < sizeof(PREFETCH_HEADER) + sizeof(PREFETCH_FILE_INFO)) goto _END_OF_FUNC;

            pFileInfo = (PPREFETCH_FILE_INFO)(pbData + sizeof(PREFETCH_HEADER));

            // Runtime detection: check which offset has plausible run count value
            // Documentation says v30 variant 2 uses 0x70, but runtime testing shows 0x74
            DWORD dwValueAtV1 = *(PDWORD)((PBYTE)pFileInfo + PREFETCH_RUN_COUNT_OFFSET_V30_1);  // 0x74
            DWORD dwValueAtV2 = *(PDWORD)((PBYTE)pFileInfo + PREFETCH_RUN_COUNT_OFFSET_V30_2);  // 0x70
            
            if (dwValueAtV2 == 0 && dwValueAtV1 > 0 && dwValueAtV1 < 100000)
            {
                // V2 offset is zero, V1 has plausible value - use V1 layout
                dwRunCountOffset    = PREFETCH_RUN_COUNT_OFFSET_V30_1;
                dwFileInfoSize      = PREFETCH_FILE_INFO_V30_1_SIZE;
            }
            else if (dwValueAtV2 > 0 && dwValueAtV2 < 100000)
            {
                // V2 offset has plausible value - use V2 layout
                dwRunCountOffset    = PREFETCH_RUN_COUNT_OFFSET_V30_2;
                dwFileInfoSize      = PREFETCH_FILE_INFO_V30_2_SIZE;
            }
            else
            {
                // Fallback to V1 layout. This was more common during testing - W10 & W11
                dwRunCountOffset    = PREFETCH_RUN_COUNT_OFFSET_V30_1;
                dwFileInfoSize      = PREFETCH_FILE_INFO_V30_1_SIZE;
            }

            if (dwDataSize < sizeof(PREFETCH_HEADER) + dwFileInfoSize) goto _END_OF_FUNC;

            dwRunCount = *(PDWORD)((PBYTE)pFileInfo + dwRunCountOffset);

            StringCchCopyW(pEntry->wszExecutableName, BUFFER_SIZE_64, pHeader->wszExecutableName);
            pEntry->dwVersion   = pHeader->dwVersion;
            pEntry->dwHash      = pHeader->dwHash;
            pEntry->dwRunCount  = dwRunCount;

            for (DWORD i = 0; i < PREFETCH_MAX_LAST_RUN_TIMES; i++)
            {
                if (pFileInfo->ftLastRunTime[i].dwHighDateTime != 0 || pFileInfo->ftLastRunTime[i].dwLowDateTime != 0)
                {
                    pEntry->ftLastRunTimes[i] = pFileInfo->ftLastRunTime[i];
                    pEntry->dwLastRunTimeCount++;
                }
            }

            ExtractFilenameStrings(pbData, dwDataSize, pHeader, pFileInfo, pEntry);
            ExtractVolumeInfo(pbData, dwDataSize, pFileInfo, pEntry);
            ExtractDirectoryStrings(pbData, dwDataSize, pFileInfo, pEntry);

            break;
        }

        default:
        {
            printf("[!] Unsupported Prefetch Version: 0x%08X\n", pHeader->dwVersion);
            goto _END_OF_FUNC;
        }
    }

    bResult = TRUE;

_END_OF_FUNC:
    return bResult;
}

static BOOL ParsePrefetchFile(IN PCWSTR pszFilePath, OUT PPREFETCH_ENTRY pEntry)
{
    HANDLE                      hFile               = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION  FileInformation     = { 0 };
    PPREFETCH_MAM_HEADER        pMamHeader          = NULL;
    PBYTE                       pbFileData          = NULL,
                                pbParsedData        = NULL;
    DWORD                       dwFileSize          = 0x00,
                                dwBytesRead         = 0x00,
                                dwParsedSize        = 0x00;
    BOOL                        bResult             = FALSE,
                                bCompressed         = FALSE;

    if (!pszFilePath || !pEntry) return FALSE;

    if ((hFile = CreateFileW(pszFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE)
    {
        printf("[!] CreateFileW Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE || dwFileSize < sizeof(PREFETCH_HEADER))
    {
        printf("[!] GetFileSize Failed Or Invalid File Size: %lu\n", dwFileSize);
        goto _END_OF_FUNC;
    }

    if (!(pbFileData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwFileSize)))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ReadFile(hFile, pbFileData, dwFileSize, &dwBytesRead, NULL) || dwBytesRead != dwFileSize)
    {
        printf("[!] ReadFile Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (GetFileInformationByHandle(hFile, &FileInformation))
    {
        pEntry->ftPrefetchCreated   = FileInformation.ftCreationTime;
        pEntry->ftPrefetchModified  = FileInformation.ftLastWriteTime;
    }

    // Check if compressed (MAM header)
    if (dwFileSize >= sizeof(PREFETCH_MAM_HEADER))
    {
        pMamHeader = (PPREFETCH_MAM_HEADER)pbFileData;

        if (pMamHeader->dwSignature == PREFETCH_COMPRESSED_SIGNATURE)
        {
            bCompressed = TRUE;

            if (!(pbParsedData = DecompressPrefetch(pbFileData, dwFileSize, &dwParsedSize)))
                goto _END_OF_FUNC;
        }
    }

    // Use raw data if not compressed
    if (!bCompressed)
    {
        pbParsedData    = pbFileData;
        dwParsedSize    = dwFileSize;
        pbFileData      = NULL;
    }

    if (!ParsePrefetchData(pbParsedData, dwParsedSize, pEntry))
        goto _END_OF_FUNC;

    StringCchCopyW(pEntry->wszPrefetchFile, MAX_PATH, PathFindFileNameW(pszFilePath));
    bResult = TRUE;

_END_OF_FUNC:
    if (hFile != INVALID_HANDLE_VALUE) 
        CloseHandle(hFile);
    if (pbFileData)
        HeapFree(GetProcessHeap(), 0, pbFileData);
    if (bCompressed && pbParsedData)
        HeapFree(GetProcessHeap(), 0, pbParsedData);
    return bResult;
}

static BOOL EnumeratePrefetch(OUT PPREFETCH_LIST pList)
{
    HANDLE              hFind                       = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW    FindData                    = { 0 };
    PPREFETCH_ENTRY     pEntry                      = NULL;
    WCHAR               szSearchPath[MAX_PATH]      = { 0 },
                        szFilePath[MAX_PATH]        = { 0 };
    BOOL                bResult                     = FALSE;

    if (!pList) return FALSE;

    if (!PrefetchListInit(pList, ARRAY_INITIAL_CAPACITY)) goto _END_OF_FUNC;

    StringCchPrintfW(szSearchPath, MAX_PATH, L"%ws\\*.pf", g_szPrefetchPath);

    if ((hFind = FindFirstFileW(szSearchPath, &FindData)) == INVALID_HANDLE_VALUE)
    {
        printf("[!] FindFirstFileW Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    do
    {
        if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        if (!ShouldProcessFile(FindData.cFileName))
            continue;

        StringCchPrintfW(szFilePath, MAX_PATH, L"%ws\\%ws", g_szPrefetchPath, FindData.cFileName);

        if (!(pEntry = PrefetchListAdd(pList)))
            continue;

        if (!ParsePrefetchFile(szFilePath, pEntry))
        {
            pList->dwCount--;
            RtlSecureZeroMemory(pEntry, sizeof(PREFETCH_ENTRY));
        }

    } while (FindNextFileW(hFind, &FindData));

    bResult = TRUE;

_END_OF_FUNC:
    if (hFind != INVALID_HANDLE_VALUE) FindClose(hFind);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static VOID PrintHelp(IN PCWSTR pszProgramName)
{
    wprintf(L"\n");
    wprintf(L"Usage: %s <options>\n\n", pszProgramName);
    wprintf(L"Options:\n");
    wprintf(L"  /o <path>       Output JSON file path (default: %s)\n", DEFAULT_OUTPUT_FILENAME);
    wprintf(L"  /p <path>       Prefetch directory path (default: %s)\n", PREFETCH_PATH);
    wprintf(L"  /b <binary>     Filter by binary name (can be specified up to %d times)\n", MAX_BINARY_FILTERS);
    wprintf(L"  /h, /?          Display this help message\n");
    wprintf(L"\n");
    wprintf(L"Examples:\n");
    wprintf(L"  %ws\n", pszProgramName);
    wprintf(L"  %ws /o Output.json\n", pszProgramName);
    wprintf(L"  %ws /b cmd.exe /b powershell.exe\n", pszProgramName);
    wprintf(L"  %ws /p 'C:\\PrefetchBackup' /o Results.json\n", pszProgramName);
    wprintf(L"\n");
}

static BOOL ParseArguments(IN INT argc, IN WCHAR* argv[])
{
    for (INT i = 1; i < argc; i++)
    {
        if (StrCmpIW(argv[i], L"/h") == 0 || StrCmpIW(argv[i], L"-h") == 0 || StrCmpIW(argv[i], L"/?") == 0 || StrCmpIW(argv[i], L"-?") == 0)
        {
            PrintHelp(PathFindFileNameW(argv[0]));
            return FALSE;
        }
        else if (StrCmpIW(argv[i], L"/o") == 0)
        {
            if (i + 1 >= argc)
            {
                printf("[!] /o Requires A File Path Argument\n");
                return FALSE;
            }
            StringCchCopyW(g_szOutputPath, MAX_PATH, argv[++i]);
        }
        else if (StrCmpIW(argv[i], L"/p") == 0)
        {
            if (i + 1 >= argc)
            {
                printf("[!] /p Requires A Directory Path Argument\n");
                return FALSE;
            }
            StringCchCopyW(g_szPrefetchPath, MAX_PATH, argv[++i]);
        }
        else if (StrCmpIW(argv[i], L"/b") == 0)
        {
            if (i + 1 >= argc)
            {
                printf("[!] /b Requires A Binary Name Argument\n");
                return FALSE;
            }
            if (g_dwBinaryFilterCount >= MAX_BINARY_FILTERS)
            {
                printf("[!] Maximum Number Of Binary Filters Reached (%d)\n", MAX_BINARY_FILTERS);
                return FALSE;
            }
            StringCchCopyW(g_szBinaryFilters[g_dwBinaryFilterCount++], MAX_PATH, argv[++i]);
        }
        else
        {
            printf("[!] Unknown Argument: %ws\n", argv[i]);
            PrintHelp(PathFindFileNameW(argv[0]));
            return FALSE;
        }
    }

    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL IsProcessElevated(IN HANDLE hProcess)
{
    HANDLE          hToken          = NULL;
    TOKEN_ELEVATION TknElevation    = { 0 };
    DWORD           dwLength        = 0x00;
    BOOL            bResult         = FALSE;

    if (!hProcess) return FALSE;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        printf("[!] OpenProcessToken Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!GetTokenInformation(hToken, TokenElevation, &TknElevation, sizeof(TOKEN_ELEVATION), &dwLength))
    {
        printf("[!] GetTokenInformation Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    bResult = TknElevation.TokenIsElevated;

_END_OF_FUNC:
    if (hToken) CloseHandle(hToken);
    return bResult;
}


int wmain(INT argc, WCHAR* argv[])
{
    PREFETCH_LIST PrefetchList = { 0 };

    if (!IsProcessElevated(GetCurrentProcess()))
    {
        printf("[!] This Program Requires Administrator Privileges\n");
        return -1;
    }

    if (!ParseArguments(argc, argv))
        return -1;

    if (!EnumeratePrefetch(&PrefetchList))
        return -1;

    if (PrefetchList.dwCount == 0x00)
    {
        printf("[!] No Prefetch Entries Found\n");
        PrefetchListFree(&PrefetchList);
        return -1;
    }

    if (!WritePrefetchJson(&PrefetchList, g_szOutputPath))
    {
        PrefetchListFree(&PrefetchList);
        return -1;
    }

    printf("[+] Wrote %lu Entries To %ws\n", PrefetchList.dwCount, g_szOutputPath);

    PrefetchListFree(&PrefetchList);
    return 0;

}
