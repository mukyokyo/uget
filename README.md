# uget

**Immortal Multi-Mirror CLI Downloader with SHA-256 & Quiet Mode**

`uget` is a highly resilient, multi-threaded command-line downloader for Windows. It is designed to aggressively download files from multiple mirrors simultaneously, seamlessly recover from connection drops or mirror failures, and verify the integrity of the downloaded file. It compiles to a single, static dependency-free executable (UCRT).

## Features

* **Multi-Mirror Downloading:** Provide multiple URLs pointing to the same file. `uget` will automatically probe them, select the fastest ones, and download chunks in parallel.
* **Immortal Resumption:** If a connection drops, it automatically retries with exponential backoff. If you stop the download (Ctrl+C) or the network goes down completely, the state is safely committed to a `.uget` tracking file. Restart the command, and it picks up exactly where it left off.
* **Adaptive Load Balancing:** Continuously monitors the speed of each mirror and dynamically shifts worker threads toward the fastest, most reliable sources.
* **Smart SHA-256 Auto-Discovery:** Automatically looks for published checksums (`.sha256`, `.sha256sum`, `SHA256SUMS`, `sha256sums.txt`) next to the file on the server. Strictly parses GNU/BSD formats and verifies the download without needing manual input.
* **Safe Mismatch Handling:** If an auto-discovered checksum fails, the `.part` file is safely preserved (exit code 2). This prevents losing gigabytes of data if the server administrator simply forgot to update their checksum file. (Manual `--sha256` mismatches will still delete the file).
* **Zero External Dependencies:** Built using native WinHTTP and Windows CNG (Cryptography Next Generation). No curl, wget, or OpenSSL libraries required.
* **Smart File Allocation:** Uses NTFS sparse files during active downloads to minimize disk fragmentation and avoid upfront zero-filling overhead.

## Installation

No installation required. Just download the `uget.exe` binary.

### Building from Source
To compile using MSYS2 / MinGW-w64 (UCRT64 environment):
```bash
g++ -O2 -s -static uget.cpp -lwinhttp -lbcrypt -o uget.exe
```

## Usage

```bash
uget [options] <URL1> [URL2 ...]
```

### Examples

**Basic Download (Will auto-discover SHA-256 if available):**
```bash
uget.exe https://example.com/file.zip
```

**Multi-Mirror Download (Aggressive):**
```bash
uget.exe -x 16 https://mirror1.com/file.iso https://mirror2.com/file.iso
```

**Download with Manual SHA-256 Verification:**
```bash
uget.exe --sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" https://example.com/data.bin
```

### Options

| Option | Description |
| :--- | :--- |
| `-o`, `-O <file>` | Output filename (default: auto-detect from headers/URL) |
| `-x <connections>` | Max concurrent connections (default: 8, max: 64) |
| `-t <streak>` | Give up after N consecutive failed attempts across all mirrors (default: 25, 0=infinite) |
| `--timeout <sec>` | Socket timeout and low-speed evaluation window in seconds (default: 15) |
| `--min-speed <KiB/s>`| Drop a ranged connection if it's slower than this over the timeout window (default: 1, 0=off) |
| `--sha256 <hash>` | Verify against this SHA-256 hex. Use `print` to show the digest, or `auto` for auto-discovery (default). |
| `--no-sha-sidecar` | Disable automatic discovery of published checksum files next to the URL. |
| `--http2` | Allow HTTP/2 (connections to the same host get multiplexed) |
| `-q`, `--quiet` | Quiet mode (suppress progress bar & info logs) |
| `-k` | Allow insecure TLS (ignore cert errors) and HTTPS->HTTP redirects |

*Without a `--sha256` hash, `<URL>.sha256`, `<URL>.sha256sum`, `SHA256SUMS` or `sha256sums.txt` next to the file is used for verification when one can be found.*