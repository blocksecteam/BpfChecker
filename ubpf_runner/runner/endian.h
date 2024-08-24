#ifndef PORTABLE_ENDIAN_H__
#define PORTABLE_ENDIAN_H__

// assume Little Endian only
#define __BYTE_ORDER __LITTLE_ENDIAN

#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)

#	define __WINDOWS__

#endif

#if defined(__linux__) || defined(__CYGWIN__)
/* Define necessary macros for the header to expose all fields. */
#   define _BSD_SOURCE
#   define __USE_BSD
#   define _DEFAULT_SOURCE
#   include <endian.h>
#   include <features.h>
/* See http://linux.die.net/man/3/endian */
// #   if !defined(__GLIBC__) || !defined(__GLIBC_MINOR__) || ((__GLIBC__ < 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ < 9)))
#       include <arpa/inet.h>
#       if defined(__BYTE_ORDER) && (__BYTE_ORDER == __LITTLE_ENDIAN)
#           define htobe16(x) htons(x)
#           define htole16(x) (x)
#           define be16toh(x) ntohs(x)
#           define le16toh(x) (x)

#           define htobe32(x) htonl(x)
#           define htole32(x) (x)
#           define be32toh(x) ntohl(x)
#           define le32toh(x) (x)

#           define htobe64(x) (((uint64_t)htonl(((uint32_t)(((uint64_t)(x)) >> 32)))) | (((uint64_t)htonl(((uint32_t)(x)))) << 32))
#           define htole64(x) (x)
#           define be64toh(x) (((uint64_t)ntohl(((uint32_t)(((uint64_t)(x)) >> 32)))) | (((uint64_t)ntohl(((uint32_t)(x)))) << 32))
#           define le64toh(x) (x)
#       elif defined(__BYTE_ORDER) && (__BYTE_ORDER == __BIG_ENDIAN)
#           define htobe16(x) (x)
#           define htole16(x) ((((((uint16_t)(x)) >> 8))|((((uint16_t)(x)) << 8)))
#           define be16toh(x) (x)
#           define le16toh(x) ((((((uint16_t)(x)) >> 8))|((((uint16_t)(x)) << 8)))

#           define htobe32(x) (x)
#           define htole32(x) (((uint32_t)htole16(((uint16_t)(((uint32_t)(x)) >> 16)))) | (((uint32_t)htole16(((uint16_t)(x)))) << 16))
#           define be32toh(x) (x)
#           define le32toh(x) (((uint32_t)le16toh(((uint16_t)(((uint32_t)(x)) >> 16)))) | (((uint32_t)le16toh(((uint16_t)(x)))) << 16))

#           define htobe64(x) (x)
#           define htole64(x) (((uint64_t)htole32(((uint32_t)(((uint64_t)(x)) >> 32)))) | (((uint64_t)htole32(((uint32_t)(x)))) << 32))
#           define be64toh(x) (x)
#           define le64toh(x) (((uint64_t)le32toh(((uint32_t)(((uint64_t)(x)) >> 32)))) | (((uint64_t)le32toh(((uint32_t)(x)))) << 32))
#       else
#           error Byte Order not supported or not defined.
#       endif
// #   endif

#elif defined(__APPLE__)

#	include <libkern/OSByteOrder.h>

#	define htobe16(x) OSSwapHostToBigInt16(x)
#	define htole16(x) OSSwapHostToLittleInt16(x)
#	define be16toh(x) OSSwapBigToHostInt16(x)
#	define le16toh(x) OSSwapLittleToHostInt16(x)

#	define htobe32(x) OSSwapHostToBigInt32(x)
#	define htole32(x) OSSwapHostToLittleInt32(x)
#	define be32toh(x) OSSwapBigToHostInt32(x)
#	define le32toh(x) OSSwapLittleToHostInt32(x)

#	define htobe64(x) OSSwapHostToBigInt64(x)
#	define htole64(x) OSSwapHostToLittleInt64(x)
#	define be64toh(x) OSSwapBigToHostInt64(x)
#	define le64toh(x) OSSwapLittleToHostInt64(x)

#	define __BYTE_ORDER    BYTE_ORDER
#	define __BIG_ENDIAN    BIG_ENDIAN
#	define __LITTLE_ENDIAN LITTLE_ENDIAN
#	define __PDP_ENDIAN    PDP_ENDIAN

#elif defined(__OpenBSD__)

#	include <endian.h>

#	define __BYTE_ORDER    BYTE_ORDER
#	define __BIG_ENDIAN    BIG_ENDIAN
#	define __LITTLE_ENDIAN LITTLE_ENDIAN
#	define __PDP_ENDIAN    PDP_ENDIAN

#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)

#	include <sys/endian.h>

#	define be16toh(x) betoh16(x)
#	define le16toh(x) letoh16(x)

#	define be32toh(x) betoh32(x)
#	define le32toh(x) letoh32(x)

#	define be64toh(x) betoh64(x)
#	define le64toh(x) letoh64(x)

#elif defined(__WINDOWS__)

#	include <winsock2.h>
#	ifdef __GNUC__
#		include <sys/param.h>
#	endif

#	if BYTE_ORDER == LITTLE_ENDIAN

#		define htobe16(x) htons(x)
#		define htole16(x) (x)
#		define be16toh(x) ntohs(x)
#		define le16toh(x) (x)

#		define htobe32(x) htonl(x)
#		define htole32(x) (x)
#		define be32toh(x) ntohl(x)
#		define le32toh(x) (x)

#		define htobe64(x) htonll(x)
#		define htole64(x) (x)
#		define be64toh(x) ntohll(x)
#		define le64toh(x) (x)

#	elif BYTE_ORDER == BIG_ENDIAN

		/* that would be xbox 360 */
#		define htobe16(x) (x)
#		define htole16(x) __builtin_bswap16(x)
#		define be16toh(x) (x)
#		define le16toh(x) __builtin_bswap16(x)

#		define htobe32(x) (x)
#		define htole32(x) __builtin_bswap32(x)
#		define be32toh(x) (x)
#		define le32toh(x) __builtin_bswap32(x)

#		define htobe64(x) (x)
#		define htole64(x) __builtin_bswap64(x)
#		define be64toh(x) (x)
#		define le64toh(x) __builtin_bswap64(x)

#	else

#		error byte order not supported

#	endif

#	define __BYTE_ORDER    BYTE_ORDER
#	define __BIG_ENDIAN    BIG_ENDIAN
#	define __LITTLE_ENDIAN LITTLE_ENDIAN
#	define __PDP_ENDIAN    PDP_ENDIAN

#elif defined(__QNXNTO__)

#	include <gulliver.h>

#	define __LITTLE_ENDIAN 1234
#	define __BIG_ENDIAN    4321
#	define __PDP_ENDIAN    3412

#	if defined(__BIGENDIAN__)

#		define __BYTE_ORDER __BIG_ENDIAN

#		define htobe16(x) (x)
#		define htobe32(x) (x)
#		define htobe64(x) (x)

#		define htole16(x) ENDIAN_SWAP16(x)
#		define htole32(x) ENDIAN_SWAP32(x)
#		define htole64(x) ENDIAN_SWAP64(x)

#	elif defined(__LITTLEENDIAN__)

#		define __BYTE_ORDER __LITTLE_ENDIAN

#		define htole16(x) (x)
#		define htole32(x) (x)
#		define htole64(x) (x)

#		define htobe16(x) ENDIAN_SWAP16(x)
#		define htobe32(x) ENDIAN_SWAP32(x)
#		define htobe64(x) ENDIAN_SWAP64(x)

#	else

#		error byte order not supported

#	endif

#	define be16toh(x) ENDIAN_BE16(x)
#	define be32toh(x) ENDIAN_BE32(x)
#	define be64toh(x) ENDIAN_BE64(x)
#	define le16toh(x) ENDIAN_LE16(x)
#	define le32toh(x) ENDIAN_LE32(x)
#	define le64toh(x) ENDIAN_LE64(x)

#else

#	error platform not supported

#endif

#endif