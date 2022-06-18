#include <cstddef>
#include <stdint.h>

bool base64_decode_mosh( const char *b64, const size_t b64_len,
		    uint8_t *raw, size_t *raw_len );

void base64_encode_mosh( const uint8_t *raw, const size_t raw_len,
		    char *b64, const size_t b64_len );
