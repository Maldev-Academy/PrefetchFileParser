#include "Headers.h"


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// General Output Utilities

static BOOL BuildVolumeMap(OUT WCHAR pVolumeMap[DRIVE_LETTER_COUNT][MAX_PATH])
{
    WCHAR   szDrive[4]              = L"A:\\";
    WCHAR   szVolumeName[MAX_PATH]  = { 0 };
    DWORD   dwSerial                = 0;

    for (WCHAR c = L'A'; c <= L'Z'; c++)
    {
        szDrive[0] = c;

        if (GetVolumeInformationW(szDrive, szVolumeName, MAX_PATH, &dwSerial, NULL, NULL, NULL, 0))
            StringCchPrintfW(pVolumeMap[c - L'A'], MAX_PATH, L"%08X", dwSerial);
        else
            pVolumeMap[c - L'A'][0] = L'\0';
    }

    return TRUE;
}

static VOID TranslateVolumePath(IN LPCWSTR pszVolumePath, IN WCHAR pVolumeMap[DRIVE_LETTER_COUNT][MAX_PATH], OUT LPWSTR pszTranslated, IN DWORD dwSize)
{
    LPCWSTR pszStart    = NULL,
            pszEnd      = NULL,
            pszRest     = NULL;
    WCHAR   szSerial[9] = { 0 };
    WCHAR   cDrive      = L'\0';

    pszStart    = StrChrW(pszVolumePath, L'{');
    pszEnd      = StrChrW(pszVolumePath, L'}');

    if (!pszStart || !pszEnd || pszEnd <= pszStart + 9)
    {
        StringCchCopyW(pszTranslated, dwSize, pszVolumePath);
        return;
    }

    // Extract serial (last 8 chars before '}')
    StringCchCopyNW(szSerial, 9, pszEnd - 8, 8);
    CharUpperW(szSerial);

    // Find matching drive letter
    for (INT i = 0; i < DRIVE_LETTER_COUNT; i++)
    {
        if (pVolumeMap[i][0] != L'\0' && StrCmpIW(pVolumeMap[i], szSerial) == 0)
        {
            cDrive = L'A' + i;
            break;
        }
    }

    if (cDrive != L'\0')
    {
        pszRest = pszEnd + 1;
        StringCchPrintfW(pszTranslated, dwSize, L"%c:%ws", cDrive, pszRest);
    }
    else
    {
        StringCchCopyW(pszTranslated, dwSize, pszVolumePath);
    }
}

static VOID FileTimeToString(IN PFILETIME pFileTime, OUT LPWSTR pszBuffer, IN DWORD dwBufferSize)
{
    SYSTEMTIME  SystemTime      = { 0 };
    FILETIME    ftLocal         = { 0 };

    if (!pFileTime || !pszBuffer || dwBufferSize == 0)
        return;

    if (pFileTime->dwHighDateTime == 0 && pFileTime->dwLowDateTime == 0)
    {
        StringCchCopyW(pszBuffer, dwBufferSize, L"N/A");
        return;
    }

    FileTimeToLocalFileTime(pFileTime, &ftLocal);
    FileTimeToSystemTime(&ftLocal, &SystemTime);

    StringCchPrintfW(pszBuffer, dwBufferSize, L"%04d-%02d-%02d %02d:%02d:%02d",
        SystemTime.wYear, SystemTime.wMonth, SystemTime.wDay, SystemTime.wHour, SystemTime.wMinute, SystemTime.wSecond);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Json Helpers

static VOID EscapeJsonStringW(IN LPCWSTR pszInput, OUT LPSTR pszOutput, IN DWORD dwOutputSize)
{
    DWORD dwOut = 0;

    if (!pszInput || !pszOutput || dwOutputSize == 0)
        return;

    while (*pszInput && dwOut < dwOutputSize - 2)
    {
        if (*pszInput < 0x80)
        {
            switch ((CHAR)*pszInput)
            {
                case '"':  if (dwOut + 2 < dwOutputSize) { pszOutput[dwOut++] = '\\'; pszOutput[dwOut++] = '"'; }  break;
                case '\\': if (dwOut + 2 < dwOutputSize) { pszOutput[dwOut++] = '\\'; pszOutput[dwOut++] = '\\'; } break;
                case '\b': if (dwOut + 2 < dwOutputSize) { pszOutput[dwOut++] = '\\'; pszOutput[dwOut++] = 'b'; }  break;
                case '\f': if (dwOut + 2 < dwOutputSize) { pszOutput[dwOut++] = '\\'; pszOutput[dwOut++] = 'f'; }  break;
                case '\n': if (dwOut + 2 < dwOutputSize) { pszOutput[dwOut++] = '\\'; pszOutput[dwOut++] = 'n'; }  break;
                case '\r': if (dwOut + 2 < dwOutputSize) { pszOutput[dwOut++] = '\\'; pszOutput[dwOut++] = 'r'; }  break;
                case '\t': if (dwOut + 2 < dwOutputSize) { pszOutput[dwOut++] = '\\'; pszOutput[dwOut++] = 't'; }  break;
                default:
                    if (*pszInput >= 0x20)
                        pszOutput[dwOut++] = (CHAR)*pszInput;
                    break;
            }
        }
        else
        {
            // Convert wide char to UTF-8
            CHAR    szUtf8[4]   = { 0 };
            INT     cbLen       = WideCharToMultiByte(CP_UTF8, 0, pszInput, 1, szUtf8, 4, NULL, NULL);
            
            for (INT i = 0; i < cbLen && dwOut < dwOutputSize - 1; i++)
                pszOutput[dwOut++] = szUtf8[i];
        }
        pszInput++;
    }
    pszOutput[dwOut] = '\0';
}

static VOID WriteJsonWideString(IN HANDLE hFile, IN LPCWSTR pszValue)
{
    LPSTR   pszEscaped  = NULL;
    DWORD   dwWritten   = 0x00,
            dwLenght    = 0x00;

    if (!pszValue)
    {
        WriteFile(hFile, "null", 4, &dwWritten, NULL);
        return;
    }

    dwLenght = lstrlenW(pszValue) * 4 + 1;  // UTF-8 can be up to 4 bytes per char
    
    if (!(pszEscaped = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLenght)))
    {
        WriteFile(hFile, "null", 4, &dwWritten, NULL);
        return;
    }

    EscapeJsonStringW(pszValue, pszEscaped, dwLenght);

    WriteFile(hFile, "\"", 1, &dwWritten, NULL);
    WriteFile(hFile, pszEscaped, lstrlenA(pszEscaped), &dwWritten, NULL);
    WriteFile(hFile, "\"", 1, &dwWritten, NULL);

    HeapFree(GetProcessHeap(), 0, pszEscaped);
}

static VOID WriteJsonDword(IN HANDLE hFile, IN DWORD dwValue)
{
    CHAR    szNumber[BUFFER_SIZE_32]    = { 0 };
    DWORD   dwWritten                   = 0;

    StringCchPrintfA(szNumber, BUFFER_SIZE_32, "%lu", dwValue);
    WriteFile(hFile, szNumber, lstrlenA(szNumber), &dwWritten, NULL);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Json Macors

#define JSON_WRITE(strA)         do { DWORD _dw; WriteFile(hFile, strA, lstrlenA(strA), &_dw, NULL); } while(0)
#define JSON_WRITE_WSTR(strW)    WriteJsonWideString(hFile, strW)
#define JSON_WRITE_DWORD(val)    WriteJsonDword(hFile, val)
#define JSON_WRITE_BOOL(val)     JSON_WRITE((val) ? "true" : "false")

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Json Output

BOOL WritePrefetchJson(IN PPREFETCH_LIST pList, IN PCWSTR pszOutputPath)
{
    HANDLE          hFile                                       = INVALID_HANDLE_VALUE;
    PPREFETCH_ENTRY pEntry                                      = NULL;
    WCHAR           szTime[BUFFER_SIZE_64]                      = { 0 };
    WCHAR           szTranslated[MAX_PATH]                      = { 0 };
    WCHAR           VolumeMap[DRIVE_LETTER_COUNT][MAX_PATH]     = { 0 };
    BOOL            bResult                                     = FALSE;

    if (!pList || !pszOutputPath) return FALSE;

    BuildVolumeMap(VolumeMap);

    if ((hFile = CreateFileW(pszOutputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
    {
        printf("[!] CreateFileW Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    JSON_WRITE("{\n");

    JSON_WRITE("  \"totalEntries\": ");
    JSON_WRITE_DWORD(pList->dwCount);
    JSON_WRITE(",\n");

    JSON_WRITE("  \"prefetchEntries\": [\n");

    for (DWORD i = 0; i < pList->dwCount; i++)
    {
        pEntry = &pList->pEntries[i];

        JSON_WRITE("    {\n");

        // Basic info
        JSON_WRITE("      \"executableName\": ");
        JSON_WRITE_WSTR(pEntry->wszExecutableName);
        JSON_WRITE(",\n");

        JSON_WRITE("      \"prefetchFile\": ");
        JSON_WRITE_WSTR(pEntry->wszPrefetchFile);
        JSON_WRITE(",\n");

        // Translate and write executable path
        TranslateVolumePath(pEntry->wszExecutablePath, VolumeMap, szTranslated, MAX_PATH);
        JSON_WRITE("      \"executablePath\": ");
        JSON_WRITE_WSTR(szTranslated);
        JSON_WRITE(",\n");

        JSON_WRITE("      \"hash\": \"");
        {
            CHAR    szHash[BUFFER_SIZE_16]  = { 0 };
            DWORD   dwWritten               = 0x00;
            StringCchPrintfA(szHash, BUFFER_SIZE_16, "%08X", pEntry->dwHash);
            WriteFile(hFile, szHash, lstrlenA(szHash), &dwWritten, NULL);
        }
        JSON_WRITE("\",\n");

        JSON_WRITE("      \"runCount\": ");
        JSON_WRITE_DWORD(pEntry->dwRunCount);
        JSON_WRITE(",\n");

        // Prefetch file created and last modified time
        FileTimeToString(&pEntry->ftPrefetchCreated, szTime, BUFFER_SIZE_64);
        JSON_WRITE("      \"prefetchCreated\": ");
        JSON_WRITE_WSTR(szTime);
        JSON_WRITE(",\n");

        FileTimeToString(&pEntry->ftPrefetchModified, szTime, BUFFER_SIZE_64);
        JSON_WRITE("      \"prefetchModified\": ");
        JSON_WRITE_WSTR(szTime);
        JSON_WRITE(",\n");

        // Last run times array
        JSON_WRITE("      \"lastRunTimes\": [\n");
        for (DWORD j = 0; j < pEntry->dwLastRunTimeCount; j++)
        {
            FileTimeToString(&pEntry->ftLastRunTimes[j], szTime, BUFFER_SIZE_64);
            JSON_WRITE("        ");
            JSON_WRITE_WSTR(szTime);
            if (j < pEntry->dwLastRunTimeCount - 1) JSON_WRITE(",");
            JSON_WRITE("\n");
        }
        JSON_WRITE("      ],\n");

        // Loaded files array
        JSON_WRITE("      \"loadedFiles\": [\n");
        for (DWORD j = 0; j < pEntry->dwLoadedFileCount; j++)
        {
            if (pEntry->ppszLoadedFiles[j])
            {
                TranslateVolumePath(pEntry->ppszLoadedFiles[j], VolumeMap, szTranslated, MAX_PATH);
                JSON_WRITE("        ");
                JSON_WRITE_WSTR(szTranslated);
            }
            if (j < pEntry->dwLoadedFileCount - 1) JSON_WRITE(",");
            JSON_WRITE("\n");
        }
        JSON_WRITE("      ],\n");

        // Directories array
        JSON_WRITE("      \"directories\": [\n");
        for (DWORD j = 0; j < pEntry->dwDirectoryCount; j++)
        {
            if (pEntry->ppszDirectories[j])
            {
                TranslateVolumePath(pEntry->ppszDirectories[j], VolumeMap, szTranslated, MAX_PATH);
                JSON_WRITE("        ");
                JSON_WRITE_WSTR(szTranslated);
            }
            if (j < pEntry->dwDirectoryCount - 1) JSON_WRITE(",");
            JSON_WRITE("\n");
        }
        JSON_WRITE("      ]\n");

        JSON_WRITE("    }");
        if (i < pList->dwCount - 1) JSON_WRITE(",");
        JSON_WRITE("\n");
    }

    JSON_WRITE("  ]\n");
    JSON_WRITE("}\n");

    bResult = TRUE;

    CloseHandle(hFile);
    return bResult;
}


