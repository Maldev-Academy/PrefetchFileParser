#pragma once
#ifndef HEADERS_H
#define HEADERS_H

#include <Windows.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <stdio.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "ntdll.lib")


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Constants

#define BUFFER_SIZE_16                  16
#define BUFFER_SIZE_32                  32
#define BUFFER_SIZE_64                  64
#define BUFFER_SIZE_128                 128
#define BUFFER_SIZE_256                 256
#define BUFFER_SIZE_512                 512
#define BUFFER_SIZE_1024                1024
#define BUFFER_SIZE_2048                2048
#define BUFFER_SIZE_4096                4096
#define BUFFER_SIZE_8192                8192

#define DRIVE_LETTER_COUNT              26
#define ARRAY_INITIAL_CAPACITY          64

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define PREFETCH_SIGNATURE              0x41434353  // "SCCA"
#define PREFETCH_COMPRESSED_SIGNATURE   0x044D414D  // "MAM\x04"


// https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc#411-format-version
/*
    17 - Used in: Windows XP, Windows 2003          [NOT SUPPORTED]
    23 - Used in: Windows Vista, Windows 7          [NOT SUPPORTED]
    26 - Used in: Windows 8.1                       [NOT SUPPORTED]
    30 - Used in: Windows 10                        [SUPPORTED]
    31 - Used in: Windows 11                        [SUPPORTED]
*/

#define PREFETCH_VERSION_WIN10          30
#define PREFETCH_VERSION_WIN11          31

// https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc?plain=1#L387
// https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc?plain=1#L423
#define PREFETCH_MAX_LAST_RUN_TIMES     8

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define PREFETCH_PATH                   L"C:\\Windows\\Prefetch"

#define DEFAULT_OUTPUT_FILENAME         L"PrefetchData.json"

#define MAX_BINARY_FILTERS              64

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Windows Defintions

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressbufferex
EXTERN_C NTSTATUS NTAPI RtlDecompressBufferEx(
    IN  USHORT  CompressionFormat,
    OUT PUCHAR  UncompressedBuffer,
    IN  ULONG   UncompressedBufferSize,
    IN  PUCHAR  CompressedBuffer,
    IN  ULONG   CompressedBufferSize,
    OUT PULONG  FinalUncompressedSize,
    IN  PVOID   WorkSpace
);

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetcompressionworkspacesize
EXTERN_C NTSTATUS NTAPI RtlGetCompressionWorkSpaceSize(
    IN  USHORT  CompressionFormatAndEngine,
    OUT PULONG  CompressBufferWorkSpaceSize,
    OUT PULONG  CompressFragmentWorkSpaceSize
);

#pragma pack(push, 1)

// https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc#31-file-header
typedef struct _PREFETCH_MAM_HEADER
{
    DWORD   dwSignature;            // 0x00 - Signature ("MAM\x04" - 0x04 indicates XPRESS Huffman compression)
    DWORD   dwUncompressedSize;     // 0x04 - Uncompressed data size
} PREFETCH_MAM_HEADER, *PPREFETCH_MAM_HEADER;

// https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc#41-file-header
typedef struct _PREFETCH_HEADER
{
    DWORD   dwVersion;              // 0x00 - Format version (17=XP, 23=Vista/7, 26=8.1, 30=10, 31=11)
    DWORD   dwSignature;            // 0x04 - Signature ("SCCA" - 0x41434353)
    DWORD   dwUnknown1;             // 0x08 - Unknown (flags? 0x01 = boot prefetch)
    DWORD   dwFileSize;             // 0x0C - File size (uncompressed)
    WCHAR   wszExecutableName[30];  // 0x10 - Executable filename (UTF-16, max 29 chars + null terminator)
    DWORD   dwHash;                 // 0x4C - Prefetch hash (path hash)
    DWORD   dwUnknown2;             // 0x50 - Unknown (possibly padding)
} PREFETCH_HEADER, *PPREFETCH_HEADER;

// https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc#442-file-metrics-array-entry---version-23
// Versions 23/26/30/31 are all the same
typedef struct _PREFETCH_FILE_METRICS_ENTRY {
    DWORD       dwStartTime;
    DWORD       dwDuration;
    DWORD       dwAverageDuration;
    DWORD       dwFilenameOffset;       // Offset into filename strings section
    DWORD       dwFilenameLength;       // Length in characters
    DWORD       dwFlags;
    ULONGLONG   ullMftReference;
} PREFETCH_FILE_METRICS_ENTRY, * PPREFETCH_FILE_METRICS_ENTRY;


// https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc#volume-information-entry---version-30
// Versions 30/31 are the same
typedef struct _PREFETCH_VOLUME_INFO {
    DWORD       dwDevicePathOffset;         // 0x00 - Volume device path offset (relative to start of volume info)
    DWORD       dwDevicePathLength;         // 0x04 - Volume device path number of characters (without end-of-string)
    FILETIME    ftCreationTime;             // 0x08 - Volume creation time (FILETIME)
    DWORD       dwSerialNumber;             // 0x10 - Volume serial number
    DWORD       dwFileReferencesOffset;     // 0x14 - File references offset (relative to start of volume info)
    DWORD       dwFileReferencesSize;       // 0x18 - File references data size
    DWORD       dwDirectoryStringsOffset;   // 0x1C - Directory strings offset (relative to start of volume info)
    DWORD       dwDirectoryStringsCount;    // 0x20 - Number of directory strings
    BYTE        padding[64];                // 0x24 - Unknown/padding (to reach 96 bytes)
} PREFETCH_VOLUME_INFO, * PPREFETCH_VOLUME_INFO;


// https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc#425-file-information---version-30---variant-1
// File information - version 30 variant 1 - 220 bytes (Windows 10 pre-1903)
typedef struct _PREFETCH_FILE_INFO_V30_1
{
    DWORD       dwMetricsArrayOffset;       // 0x00 - File metrics array offset
    DWORD       dwMetricsArrayCount;        // 0x04 - Number of file metrics array entries
    DWORD       dwTraceChainsOffset;        // 0x08 - Trace chains array offset
    DWORD       dwTraceChainsCount;         // 0x0C - Number of trace chains array entries
    DWORD       dwFilenameStringsOffset;    // 0x10 - Filename strings offset
    DWORD       dwFilenameStringsSize;      // 0x14 - Filename strings data size
    DWORD       dwVolumesInfoOffset;        // 0x18 - Volumes information offset
    DWORD       dwVolumesInfoCount;         // 0x1C - Number of volumes
    DWORD       dwVolumesInfoSize;          // 0x20 - Volumes information data size
    DWORD       dwTotalDirectoryCount;      // 0x24 - Total number of directory strings (across all volumes)
    DWORD       dwUnknown1;                 // 0x28 - Unknown
    FILETIME    ftLastRunTime[8];           // 0x2C - Last run times (FILETIME array, 8 entries, 64 bytes)
    DWORD       dwUnknown2;                 // 0x6C - Unknown (remnant data after 8 run times filled)
    DWORD       dwUnknown3;                 // 0x70 - Unknown
    DWORD       dwRunCount;                 // 0x74 - Run count
    BYTE        padding[100];               // 0x78 - Unknown/padding (to reach 220 bytes)
} PREFETCH_FILE_INFO_V30_1, *PPREFETCH_FILE_INFO_V30_1;

// https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc#426-file-information---version-30---variant-2
// File information - version 30 variant 2 / version 31 - 212 bytes (Windows 10 1903+ / Windows 11)
typedef struct _PREFETCH_FILE_INFO_V30_2
{
    DWORD       dwMetricsArrayOffset;       // 0x00 - File metrics array offset
    DWORD       dwMetricsArrayCount;        // 0x04 - Number of file metrics array entries
    DWORD       dwTraceChainsOffset;        // 0x08 - Trace chains array offset
    DWORD       dwTraceChainsCount;         // 0x0C - Number of trace chains array entries
    DWORD       dwFilenameStringsOffset;    // 0x10 - Filename strings offset
    DWORD       dwFilenameStringsSize;      // 0x14 - Filename strings data size
    DWORD       dwVolumesInfoOffset;        // 0x18 - Volumes information offset
    DWORD       dwVolumesInfoCount;         // 0x1C - Number of volumes
    DWORD       dwVolumesInfoSize;          // 0x20 - Volumes information data size
    DWORD       dwTotalDirectoryCount;      // 0x24 - Total number of directory strings (across all volumes)
    DWORD       dwUnknown1;                 // 0x28 - Unknown
    FILETIME    ftLastRunTime[8];           // 0x2C - Last run times (FILETIME array, 8 entries, 64 bytes)
    DWORD       dwUnknown2;                 // 0x6C - Unknown (remnant data after 8 run times filled)
    DWORD       dwRunCount;                 // 0x70 - Run count
    BYTE        padding[96];                // 0x74 - Unknown/padding (to reach 212 bytes)
} PREFETCH_FILE_INFO_V30_2, *PPREFETCH_FILE_INFO_V30_2;

// Common file information structure (shared fields up to offset 0x6C)
typedef struct _PREFETCH_FILE_INFO
{
    DWORD       dwMetricsArrayOffset;       // 0x00 - File metrics array offset
    DWORD       dwMetricsArrayCount;        // 0x04 - Number of file metrics array entries
    DWORD       dwTraceChainsOffset;        // 0x08 - Trace chains array offset
    DWORD       dwTraceChainsCount;         // 0x0C - Number of trace chains array entries
    DWORD       dwFilenameStringsOffset;    // 0x10 - Filename strings offset
    DWORD       dwFilenameStringsSize;      // 0x14 - Filename strings data size
    DWORD       dwVolumesInfoOffset;        // 0x18 - Volumes information offset
    DWORD       dwVolumesInfoCount;         // 0x1C - Number of volumes
    DWORD       dwVolumesInfoSize;          // 0x20 - Volumes information data size
    DWORD       dwTotalDirectoryCount;      // 0x24 - Total number of directory strings (across all volumes)
    DWORD       dwUnknown1;                 // 0x28 - Unknown
    FILETIME    ftLastRunTime[8];           // 0x2C - Last run times (FILETIME array, 8 entries, 64 bytes)
} PREFETCH_FILE_INFO, *PPREFETCH_FILE_INFO;
#pragma pack(pop)

#define PREFETCH_FILE_INFO_V30_1_SIZE       220
#define PREFETCH_FILE_INFO_V30_2_SIZE       212
#define PREFETCH_RUN_COUNT_OFFSET_V30_1     0x74
#define PREFETCH_RUN_COUNT_OFFSET_V30_2     0x70

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Output Structures

// Parsed prefetch entry containing extracted information
typedef struct _PREFETCH_ENTRY
{
    WCHAR       wszExecutableName[BUFFER_SIZE_64];              // Executable filename (from header)
    WCHAR       wszPrefetchFile[MAX_PATH];                      // Prefetch filename 
    DWORD       dwRunCount;                                     // Number of times the executable has been run
    FILETIME    ftLastRunTimes[PREFETCH_MAX_LAST_RUN_TIMES];    // Last 8 execution timestamps
    DWORD       dwLastRunTimeCount;                             // Number of valid entries in ftLastRunTimes
    DWORD       dwVersion;                                      // Prefetch format version 
    DWORD       dwHash;                                         // Prefetch path hash
    WCHAR       wszExecutablePath[MAX_PATH];                    // Full path of executable 
    LPWSTR*     ppszLoadedFiles;                                // Array of loaded file paths (DLLs, etc.)
    DWORD       dwLoadedFileCount;                              // Number of entries in ppszLoadedFiles
    LPWSTR*     ppszDirectories;                                // Array of accessed directories
    DWORD       dwDirectoryCount;                               // Number of entries in ppszDirectories
    WCHAR       wszVolumeDevicePath[MAX_PATH];                  // Volume device path 
    DWORD       dwVolumeSerialNumber;                           // Volume serial number
    FILETIME    ftVolumeCreationTime;                           // Volume creation time
    FILETIME    ftPrefetchCreated;                              // Prefetch file creation time (from file system)
    FILETIME    ftPrefetchModified;                             // Prefetch file last modified time (from file system)
} PREFETCH_ENTRY, *PPREFETCH_ENTRY;

// Dynamic array of prefetch entries
typedef struct _PREFETCH_LIST
{
    DWORD               dwCount;        
    DWORD               dwCapacity;     
    PPREFETCH_ENTRY     pEntries;       
} PREFETCH_LIST, *PPREFETCH_LIST;


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Functions

BOOL WritePrefetchJson(IN PPREFETCH_LIST pList, IN PCWSTR pszOutputPath);


#endif // !HEADERS_H
