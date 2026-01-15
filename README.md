# Windows Prefetch Parser BOF

A Beacon Object File (BOF) that parses Windows Prefetch files to extract execution artifacts. This tool helps identify program execution history on Windows systems.

## What is Prefetch?

Windows Prefetch (.pf files) stores information about frequently executed applications to speed up their loading. These files contain valuable forensic artifacts including:
- Executable name and path
- Number of times executed (run count)
- Last 8 execution timestamps
- Files and directories accessed by the program

## Files

- `prefetch_bof.c` - Main BOF source code
- `prefetch.cna` - Aggressor script to load and execute the BOF
- `Makefile` - Build script for compiling
- `beacon.h` - Beacon API header file (from Cobalt Strike)

## Features

- Parses both compressed (Windows 10+) and uncompressed prefetch files
- Supports Windows 10 (version 30) and Windows 11 (version 31) formats
- Extracts execution timestamps, run counts, and file metadata
- Optional filtering by filename
- Custom prefetch directory path support
- In-memory execution via BOF
- Supports both x64 and x86 architectures

## Compilation

### Prerequisites

Install MinGW-w64 cross-compiler:

```bash
# On Ubuntu/Debian
sudo apt-get install mingw-w64

# On macOS with Homebrew
brew install mingw-w64
```

### Build

To compile both x64 and x86 versions:

```bash
make -f Makefileall
```

To compile only x64:

```bash
make -f Makefilex64
```

To compile only x86:

```bash
make -f Makefilex86
```

After compilation, you should have:
- `prefetch.x64.o` - 64-bit BOF
- `prefetch.x86.o` - 32-bit BOF

## Installation in Cobalt Strike

1. Create a directory for the BOF (e.g., `bofs/prefetch/`)
2. Copy the compiled `.o` files and the `.cna` script to this directory:
   ```
   bofs/prefetch/
   ├── prefetch.cna
   ├── prefetch.x64.o
   └── prefetch.x86.o
   ```
3. Load the Aggressor script in Cobalt Strike:
   - Go to `Cobalt Strike` → `Script Manager`
   - Click `Load` and select `prefetch.cna`

**Important**: The `.cna` script expects the `.o` files to be in the same directory as the script itself.

## Usage

In a Beacon console:

```
prefetch [path] [filter1 filter2 ...]
```

### Examples

**Parse all prefetch files (default location):**
```
prefetch
```

**Parse prefetch files from a custom directory:**
```
prefetch C:\PrefetchBackup
prefetch D:\Forensics\Prefetch
```

**Filter by specific executables:**
```
prefetch cmd.exe powershell.exe
prefetch notepad.exe calc.exe chrome.exe
prefetch mshta.exe wscript.exe cscript.exe
```

**Custom path with filters:**
```
prefetch C:\Custom\Path notepad.exe.pf calc.exe.pf
```

### Arguments

- `path` - (Optional) Custom prefetch directory path. Default: `C:\Windows\Prefetch`
- `filters` - (Optional) One or more **executable names** to filter results (e.g., `cmd.exe`, `powershell.exe`)

**Note**: 
- The path argument must contain a backslash (\\) or colon (:) to be recognized as a path
- Filters match against the **executable name** (e.g., `cmd.exe`), not the full prefetch filename (e.g., `CMD.EXE-0BD30981.pf`)
- Filter matching is case-insensitive

## Output Format

The BOF outputs detailed information for each prefetch file:

```
========== Prefetch Analysis ==========
Total Entries: 245

[1] CMD.EXE
  Prefetch File: CMD.EXE-0BD30981.pf
  Hash: 0BD30981
  Run Count: 127
  Version: 30
  Created: 2024-01-15 09:23:45
  Modified: 2024-01-20 14:32:10
  Last Run Times:
    [1] 2024-01-20 14:32:08
    [2] 2024-01-20 12:15:33
    [3] 2024-01-19 16:47:22
    ...

[2] POWERSHELL.EXE
  ...
```
## Requirements

- **Administrator privileges**: Required to access `C:\Windows\Prefetch`
- **Windows 10 or 11**: Supports prefetch versions 30 and 31
- **Architecture**: Both x64 and x86 beacons supported

## Limitations

- Does not extract full file paths (only basic metadata)
- Does not resolve volume device paths to drive letters
- Maximum 64 filename filters
- Sequential processing (not parallelized)

## Use Cases

- **Incident Response**: Identify executed malware and suspicious programs
- **Forensic Analysis**: Determine program execution history and timeline
- **Threat Hunting**: Find evidence of lateral movement tools (PSExec, WMI, etc.)
- **Persistence Detection**: Identify startup programs and scheduled tasks

## Security Note

This tool is intended for authorized security testing, incident response, and forensic analysis only. Unauthorized use may be illegal in your jurisdiction.

## Technical Details

### Supported Prefetch Versions

- **Version 30**: Windows 10 (all builds)
- **Version 31**: Windows 11

### Compression

The BOF automatically handles:
- Compressed prefetch files (XPRESS_HUFF algorithm)
- Uncompressed prefetch files
- MAM (Memory And Module) header detection

### Memory Management

All memory allocations use Beacon's heap and are properly freed after parsing to avoid memory leaks in the target process.

## Troubleshooting

**"FindFirstFileW failed"**
- Verify the prefetch path exists
- Ensure you have administrator privileges
- Check if prefetch is enabled (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`)

**"Invalid prefetch signature"**
- File may be corrupted
- Not a valid prefetch file
- Check file format and version

**"Unsupported prefetch version"**
- BOF only supports Windows 10/11 (versions 30 and 31)
- Earlier Windows versions (XP, Vista, 7, 8.1) are not supported

## Refrence
Based on:
https://github.com/Maldev-Academy/PrefetchFileParser
