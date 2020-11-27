#ifndef ENDIAN_H
#define	ENDIAN_H

#ifdef _MSC_VER
    #include <stdlib.h>
    #define bswap_32(x) _byteswap_ulong(x)
    #define bswap_64(x) _byteswap_uint64(x)
#elif defined(__APPLE__)
    // Mac OS X / Darwin features
    #include <libkern/OSByteOrder.h>
    #define bswap_32(x) OSSwapInt32(x)
    #define bswap_64(x) OSSwapInt64(x)
#elif defined(__sun) || defined(sun)
    #include <sys/byteorder.h>
    #define bswap_32(x) BSWAP_32(x)
    #define bswap_64(x) BSWAP_64(x)
#elif defined(__FreeBSD__)
    #include <sys/endian.h>
    #define bswap_32(x) bswap32(x)
    #define bswap_64(x) bswap64(x)
#elif defined(__OpenBSD__)
    #include <sys/types.h>
    #define bswap_32(x) swap32(x)
    #define bswap_64(x) swap64(x)
#elif defined(__NetBSD__)
    #include <sys/types.h>
    #include <machine/bswap.h>
    #if defined(__BSWAP_RENAME) && !defined(__bswap_32)
        #define bswap_32(x) bswap32(x)
        #define bswap_64(x) bswap64(x)
    #endif
#else
    #include <byteswap.h>
#endif

bool is_big_endian(void) {
    union {
        uint32_t i;
        char c[4];
    } bint = {0x01020304};
    return bint.c[0] == 1; 
}

uint64_t system_to_big_endian(uint64_t system) {
	if (is_big_endian()) return system;
	return bswap_64(system);
}

uint64_t big_to_system_endian(uint64_t big) {
	if (is_big_endian()) return big;
	return bswap_64(big);
}

uint32_t system_to_big_endian(uint32_t system) {
	if (is_big_endian()) return system;
	return bswap_32(system);
}

uint32_t big_to_system_endian(uint32_t big) {
	if (is_big_endian()) return big;
	return bswap_32(big);
}

#endif
