# Port Scanner BOF

A Beacon Object File (BOF) version of the port scanner for Cobalt Strike.

## Files

- `portscanner_bof.c` - Main BOF source code
- `beacon.h` - Beacon API header file
- `portscanner.cna` - Aggressor script to load and execute the BOF
- `Makefile` - Build script for compiling

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
make all
```

To compile only x64:

```bash
make x64
```

To compile only x86:

```bash
make x86
```

To clean build artifacts:

```bash
make clean
```

After compilation, you should have:
- `portscanner.x64.o` - 64-bit BOF
- `portscanner.x86.o` - 32-bit BOF

## Installation in Cobalt Strike

1. Create a directory for the BOF (e.g., `bofs/portscanner/`)
2. Copy the compiled `.o` files and the `.cna` script to this directory:
   ```
   bofs/portscanner/
   ├── portscanner.cna
   ├── portscanner.x64.o
   └── portscanner.x86.o
   ```
3. Load the Aggressor script in Cobalt Strike:
   - Go to `Cobalt Strike` → `Script Manager`
   - Click `Load` and select `portscanner.cna`
   
**Important**: The `.cna` script expects the `.o` files to be in the same directory as the script itself (using `script_resource()`)

## Usage

In a Beacon console:

```
portscanner <ip> <ports>
```

### Examples

```
portscanner 192.168.1.1 80,443,8080
portscanner 10.0.0.5 22,3389,445,139
portscanner 172.16.0.100 21,22,23,25,80,443,3389,8080
```

### Arguments

- `ip` - Target IP address to scan
- `ports` - Comma-separated list of ports to scan (no spaces)

## Features

- Lightweight in-memory execution
- No files written to disk
- Uses Beacon's process memory
- Supports both x64 and x86 architectures
- Timeout-based scanning (1 second per port)
- HTTP probe on successful connections

## Output

The scanner will report each port as either:
- `[+] ip:port is open` - Port is accessible
- `[-] ip:port is closed` - Port is not accessible or filtered

## Differences from Original

The BOF version has several key differences from the standalone executable:

1. **No main() function** - Uses `go()` as the entry point
2. **Dynamic function resolution** - Uses Beacon's API to call Windows functions via DECLSPEC_IMPORT
3. **Beacon output** - Uses `BeaconPrintf()` instead of `printf()`
4. **Argument parsing** - Uses Beacon's data parser instead of `argv`
5. **Socket per port** - Creates a new socket for each port to avoid connection issues

## Limitations

- No parallel scanning (scans ports sequentially)
- Fixed 1-second timeout per port

## Improvements to Consider

1. Implement parallel port scanning
2. Add configurable timeout
3. Add protocol detection beyond HTTP
4. Support for port ranges (e.g., 80-100)

## Security Note

This tool is intended for authorized security testing and red team operations only. Unauthorized port scanning may be illegal in your jurisdiction.
