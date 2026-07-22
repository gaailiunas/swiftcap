# Swiftcap

A high-performance packet processing engine where speed directly depends on your disk type. Faster disks (like NVMe SSDs) make Swiftcap faster, while slower disks (like HDDs) limit its speed.

## Overview

Swiftcap efficiently processes network packet capture (PCAP) files using multi-threading and smart disk handling. Key features:
- Disk speed determines performance (NVMe SSDs recommended)
- Supports common PCAP formats
- Uses multi-threading for parallel processing
- Optimized for low overhead

## Getting Started

### Prerequisites
- CMake (for building)
- GCC or compatible C compiler

### Installation
1. Clone the repository:
   `git clone https://github.com/gaailiunas/swiftcap.git`
2. Navigate into the project directory:
   `cd swiftcap`
3. Build with CMake:
   ```
   mkdir build && cd build
   cmake -DCMAKE_BUILD_TYPE=Release ..
   cmake --build .
   ```

### Usage

`./build/swiftcap /path/to/input.pcap`

## Performance

Speed scales with disk type:
- **NVMe SSD**: Best performance
- **SATA SSD**: Good performance
- **HDD**: Slower due to mechanical limitations

Optimal performance is achieved when:
- Disk has sufficient read throughput
- Enough worker threads are used (auto-detects by default)

## License

MIT (see [LICENSE](LICENSE) for details)