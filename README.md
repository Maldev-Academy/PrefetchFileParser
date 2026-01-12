# PrefetchFileParser

A lightweight Windows Prefetch file parser to extract programs' execution history.


<br>

### Quick Links

[Maldev Academy Home](https://maldevacademy.com?ref=gh)

[Maldev Database](https://search.maldevacademy.com?ref=gh)
  
[Malware Development Course Syllabus](https://maldevacademy.com/maldev-course/syllabus?ref=gh)

[Offensive Phishing Operations Course Syllabus](https://maldevacademy.com/phishing-course/syllabus?ref=gh)

[Ransomware Internals, Simulation and Detection Course Syllabus](https://maldevacademy.com/ransomware-course/syllabus?ref=gh)

<br>

## Features

* Parses Windows Prefetch files (`.pf`) from Windows 10/11 (version 30/31).
* Extracts execution timestamps, run counts, loaded DLLs, and accessed directories.
* Filters by specific executable names.
* Outputs the data in JSON format.

<br>


## Prefetch Files In Windows

Prefetch is a Windows performance feature that monitors application startup and records execution traces to speed up future launches. Each time a program runs, Windows creates or updates a `.pf` file under `C:\Windows\Prefetch` containing metadata about that execution. This metadata typically includes timestamps, run counts, referenced files (including DLLs), file paths, and accessed directories. Prefetch files can be utilized in both offensive and defensive contexts:

* **Offensive Context** - Developed for the *Persistence Modules* of the [Maldev Academy Malware Development Course](https://maldevacademy.com/maldev-course/syllabus?ref=gh) to identify frequently executed programs.

* **Defensive Context** - Investigate executed applications and detect techniques like DLL sideloading.


<br>

## References:

* [Windows Prefetch File Format](https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc) by [Joachim Metz](https://github.com/joachimmetz)
* [Forensic Analysis of Prefetch files in Windows](https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/)

<br>


## Usage


```
Usage: PrefetchFileParser.exe <options>

Options:
  /o <path>       Output JSON file path (default: PrefetchData.json)
  /p <path>       Prefetch directory path (default: C:\Windows\Prefetch)
  /b <binary>     Filter by binary name (can be specified up to 64 times)
  /h, /?          Display this help message

Examples:
  PrefetchFileParser.exe
  PrefetchFileParser.exe /o Output.json
  PrefetchFileParser.exe /b cmd.exe /b powershell.exe
  PrefetchFileParser.exe /p 'C:\PrefetchBackup' /o Results.json
```

> **Note:** The `/b` filter requires the full filename including `.exe` extension.

<br>

## Example

* Running the tool to extract `Chrome.exe`'s history.

<img width="1168" height="649" alt="image" src="https://github.com/user-attachments/assets/ce33c355-9d89-46da-b022-be931bea690b" />

<br>

* Loaded files reveal `DLLEXTRACTCHROMIUMSECRETS.DLL`, which is a part of our [DumpBrowserSecrets](https://github.com/Maldev-Academy/DumpBrowserSecrets) repo.

<img width="1744" height="510" alt="image" src="https://github.com/user-attachments/assets/d23ace2b-9e66-41a3-a3c0-f6bf055bdea1" />

