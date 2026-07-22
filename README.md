# Swiftcap

A high-performance packet processing engine where speed directly depends on your disk type. Faster disks (like NVMe SSDs) make Swiftcap faster, while slower disks (like HDDs) limit its speed.

## Overview

Swiftcap efficiently processes network packet capture (PCAP) files using multi-threading and smart disk handling. Key features:
- **Disk-bound performance**: Speed scales with storage medium (NVMe SSDs recommended)
   - Supports common PCAP formats
   - Multi-threaded parallel processing
   - Optimized for low overhead
- **Binary output generation**: Creates compact binary files with structured packet metadata for future frontend (lazy loading + indexing)

## Getting Started

### Prerequisites
- CMake (for building)
- GCC or compatible C compiler

### Installation
1. Clone the repository:
```bash
 git clone https://github.com/gaailiunas/swiftcap.git
```
2. Navigate into the project directory:
```bash
 cd swiftcap
```
3. Build with CMake:
```bash
 mkdir build && cd build
 cmake -DCMAKE_BUILD_TYPE=Release ..
 cmake --build .
```

### Usage

```bash
 ./build/swiftcap /path/to/input.pcap
```

## Performance

Speed scales with disk type:
- **NVMe SSD**: Best performance (recommended for processing large PCAP files)
- **SATA SSD**: Good performance
- **HDD**: Slower due to mechanical limitations

Optimal performance is achieved when:
- Disk has sufficient read throughput (≥ 500 MB/s recommended)
- Enough worker threads are used (auto-detected by default)

## Binary Output Format

Swiftcap generates binary files with the following structure per packet:
- 8-byte packet number (unsigned long long)
- 8-byte file offset (unsigned long long)

> [!NOTE]
> The binary format is experimental and may change during development.

## License

MIT (see [LICENSE](LICENSE) for details)