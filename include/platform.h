#ifndef PLATFORM_H
#define PLATFORM_H

// Platform-specific includes and definitions for cross-platform compatibility
// This header provides portable byte-order conversion functions

#include <cstdint>
#include <cstring>

// Portable byte order conversion
// Works on any platform without requiring system headers
namespace PortableNet {

inline uint16_t swapBytes16(uint16_t value) {
    return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
}

inline uint32_t swapBytes32(uint32_t value) {
    return ((value & 0xFF000000) >> 24) |
           ((value & 0x00FF0000) >> 8)  |
           ((value & 0x0000FF00) << 8)  |
           ((value & 0x000000FF) << 24);
}

// Check system endianness at runtime
inline bool isLittleEndian() {
    uint16_t test = 0x0001;
    return *reinterpret_cast<uint8_t*>(&test) == 0x01;
}

// Network to host byte order (16-bit)
// Network byte order is always big-endian
inline uint16_t netToHost16(uint16_t netValue) {
    if (isLittleEndian()) {
        return swapBytes16(netValue);
    }
    return netValue;
}

// Network to host byte order (32-bit)
inline uint32_t netToHost32(uint32_t netValue) {
    if (isLittleEndian()) {
        return swapBytes32(netValue);
    }
    return netValue;
}

// Host to network byte order (16-bit)
inline uint16_t hostToNet16(uint16_t hostValue) {
    return netToHost16(hostValue);  // Same operation
}

// Host to network byte order (32-bit)
inline uint32_t hostToNet32(uint32_t hostValue) {
    return netToHost32(hostValue);  // Same operation
}

// ----------------------------------------------------------------------------
// Alignment-safe field readers.
//
// Packet buffers are raw byte arrays with no alignment guarantee -- a TCP
// header, for example, sits at offset 34 (14-byte Ethernet + 20-byte IP),
// which is not 4-byte aligned. Dereferencing a `const uint32_t*` cast onto
// such an address is undefined behavior in C++: it happens to work on x86
// (which tolerates unaligned loads) but is a guaranteed SIGBUS/crash on
// strict-alignment architectures like ARM, and UBSan will flag it either
// way. memcpy into a properly-aligned local is the portable fix and modern
// compilers optimize it down to the same load instruction on x86.
inline uint16_t readBE16(const uint8_t* p) {
    uint16_t v;
    std::memcpy(&v, p, sizeof(v));
    return netToHost16(v);
}

inline uint32_t readBE32(const uint8_t* p) {
    uint32_t v;
    std::memcpy(&v, p, sizeof(v));
    return netToHost32(v);
}

} // namespace PortableNet

#endif // PLATFORM_H
