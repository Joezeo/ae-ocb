#include <iostream>
#include <sstream>
#include <stdio.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "crypto.h"
#include "prng.h"
#include "fatal_assert.h"

#define NONCE_FMT "%016" PRIx64
#define DUMP_NAME_FMT "%-10s "

using namespace std;
using namespace Crypto;

PRNG prng;

const size_t MESSAGE_SIZE_MAX     = (2048 - 16);
const size_t MESSAGES_PER_SESSION = 256;
const size_t NUM_SESSIONS         = 64;

bool verbose = false;

void hexdump( const void *buf, size_t len, const char *name ) {
  const unsigned char *data = (const unsigned char *) buf;
  printf( DUMP_NAME_FMT, name );
  for ( size_t i = 0; i < len; i++ ) {
    printf( "%02x", data[ i ] );
  }
  printf( "\n" );
}

void hexdump( const Crypto::AlignedBuffer &buf, const char *name ) {
  hexdump( buf.data(), buf.len(), name );
}

void hexdump( const std::string &buf, const char *name ) {
  hexdump( buf.data(), buf.size(), name );
}


int main(int argc, const char** argv) {
    cout << "Hello World!" << endl;
}
