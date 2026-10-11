# P2P File Sharing in C

A peer-to-peer file-sharing application written in C using TCP sockets and POSIX threads. A tracker helps peers discover each other, while peers transfer file pieces directly.

## Features

- Tracker-based peer discovery
- TCP communication between peers
- File splitting into pieces of up to 256 KiB
- Piece-level integrity verification using FNV-1a hashes
- Download resumption using already verified pieces
- File reconstruction and final integrity verification

## Requirements

- Linux or Ubuntu on WSL
- GCC
- POSIX threads

## Compile

```bash
gcc -Wall -Wextra p2p.c -o p2p -pthread
```

## Usage

### 1. Start the tracker

```bash
./p2p tracker 9000
```

### 2. Start a seed peer

In another terminal:

```bash
./p2p seed A 9001 9000 sample.txt
```

### 3. Download the file

In a third terminal:

```bash
./p2p download B 9002 9000 sample.txt.meta --exit-when-done
```

The downloader discovers peers through the tracker, downloads missing pieces, verifies them, reconstructs the file, and exits when complete.

Without `--exit-when-done`, the downloader continues running as a peer after completion.

## Multi-piece testing

Create a 512 KiB test file:

```bash
python3 -c "with open('test_large.bin', 'wb') as f: f.write(bytes(range(256)) * 2048)"
```

Seed it:

```bash
./p2p seed C 9003 9000 test_large.bin
```

Download it from another terminal:

```bash
./p2p download D 9004 9000 test_large.bin.meta --exit-when-done
```

Compare the original and reconstructed files:

```bash
cmp test_large.bin data_D/test_large.bin
```

If `cmp` produces no output and returns success, the files match exactly.

## Architecture

1. **Tracker:** Maintains registered peer information and helps peers discover one another.
2. **Seed peer:** Serves requested file pieces to other peers.
3. **Downloader:** Requests pieces, checks their lengths and hashes, and stores verified pieces.
4. **Reconstruction:** Combines the pieces and verifies the final file.

## Integrity note

FNV-1a detects accidental corruption but is not a cryptographic hash and does not protect against malicious tampering.

## Limitations

- Piece downloads are sequential in the current implementation.
- Peers must be able to connect over the configured TCP ports.
- This is an educational project, not a production-hardened file-sharing service.

## Testing performed

- Single-piece transfer between peers
- Piece integrity verification
- File reconstruction and comparison using `cmp`
- Two-piece transfer using a 512 KiB file
- Comparison of the original and reconstructed multi-piece files
