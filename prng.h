#ifndef PRNG_HPP
#define PRNG_HPP

#include <string>
#include <stdint.h>
#include <fstream>

#include "crypto.h"

/* Read random bytes from /dev/urandom.

   We rely on stdio buffering for efficiency. */

static const char rdev[] = "/dev/urandom";

using namespace Crypto;

class PRNG {
 private:
  std::ifstream randfile;

  /* unimplemented to satisfy -Weffc++ */
  PRNG( const PRNG & );
  PRNG & operator=( const PRNG & );

 public:
  PRNG() : randfile( rdev, std::ifstream::in | std::ifstream::binary ) {}

  void fill( void *dest, size_t size ) {
    if ( 0 == size ) {
      return;
    }

    randfile.read( static_cast<char *>( dest ), size );
    if ( !randfile ) {
      throw CryptoException( "Could not read from " + std::string( rdev ) );
    }
  }

  uint8_t uint8() {
    uint8_t x;
    fill( &x, 1 );
    return x;
  }

  uint32_t uint32() {
    uint32_t x;
    fill( &x, 4 );
    return x;
  }

  uint64_t uint64() {
    uint64_t x;
    fill( &x, 8 );
    return x;
  }
};

#endif

