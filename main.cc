#include <iostream>
#include <sstream>
#include <stdio.h>
#include <cassert>

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

static std::string random_payload( void ) {
  const size_t len = prng.uint32() % MESSAGE_SIZE_MAX;
  char buf[ MESSAGE_SIZE_MAX ];
  prng.fill( buf, len );

  std::string payload( buf, len );
  return payload;
}

static void test_bad_decrypt( Session &decryption_session ) {
  std::string bad_ct = random_payload();

  bool got_exn = false;
  try {
    decryption_session.decrypt( bad_ct );
  } catch ( const CryptoException &e ) {
    got_exn = true;

    /* The "bad decrypt" exception needs to be non-fatal, otherwise we are
       vulnerable to an easy DoS. */
    fatal_assert( ! e.fatal );
  }

  fatal_assert( got_exn );
}

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
    string base64 = "fDSpx96gmdY+CPPiINZKNQ";
    cout << "AES key: " << base64 << endl;
    Base64Key key(base64);

    string wiresharkHex = "80000000000000003556203d7872423426e734314f41d4576be2f7d2bf390995f2af56b1bf1f46c4d7180f4e9dc94f07513902c8049578096d8b342f36aa46501e3a0cf212a6327318a4f1c736f4329cabb92cd9cdd4342252c0e54808310fd9c624c3fda206dafdce24b98c0d8fb234fae023a6ad6d8e4b9bde662928674520b0a4acf3199572145cad1445b5b90f33201e";

    char *cons = new char[146] {-128, 0, 0, 0, 0, 0, 0, 0, 53, 86, 32, 61, 120, 114, 66, 52, 38, -25, 52, 49, 79, 65, -44, 87, 107, -30, -9, -46, -65, 57, 9, -107, -14, -81, 86, -79, -65, 31, 70, -60, -41, 24, 15, 78, -99, -55, 79, 7, 81, 57, 2, -56, 4, -107, 120, 9, 109, -117, 52, 47, 54, -86, 70, 80, 30, 58, 12, -14, 18, -90, 50, 115, 24, -92, -15, -57, 54, -12, 50, -100, -85, -71, 44, -39, -51, -44, 52, 34, 82, -64, -27, 72, 8, 49, 15, -39, -58, 36, -61, -3, -94, 6, -38, -3, -50, 36, -71, -116, 13, -113, -78, 52, -6, -32, 35, -90, -83, 109, -114, 75, -101, -34, 102, 41, 40, 103, 69, 32, -80, -92, -84, -13, 25, -107, 114, 20, 92, -83, 20, 69, -75, -71, 15, 51, 32, 30};
    string src(cons, 146);
    /*
    string src;
    bool suc = Base64Decode(content, &src);
    src = src.substr(0, src.size() - 1);
    if (suc) {
        cout << "Base64 decode content success." << endl;
        for (int i = 0; i < src.size(); i++) {
            printf("%d ", src.data()[i]);
        }
        cout << endl;
    } else {
        throw CryptoException( "Base64 decode content failed." );
    }
    */ 
    cout << "Wireshark Hex: " << wiresharkHex << endl;
    cout << " --- " << endl;
    hexdump(src, "Transfered Hex: ");
    cout << " --- " << endl;

    Session session(key);
    try {
        session.decrypt(src);
        cout << "Verify decrypt success." << endl;
        cout << " --- " << endl;
    } catch ( const CryptoException &e ) {
        cout << "CryptoExcetion catched: " << e.text << endl;
        cout << " --- " << endl;
        /* The "bad decrypt" exception needs to be non-fatal, otherwise we are
        vulnerable to an easy DoS. */
        fatal_assert( ! e.fatal );
    }

    Session encryption_session( key );
    Session decryption_session( key );

    uint64_t nonce_int = prng.uint64();

    bool show_onece = false;
    assert(!show_onece);
    for ( size_t i=0; i<MESSAGES_PER_SESSION; i++ ) {
        Nonce nonce( nonce_int );
        fatal_assert( nonce.val() == nonce_int );

        std::string plaintext = random_payload();

        std::string ciphertext = encryption_session.encrypt( Message( nonce, plaintext ) );

        if (!show_onece) {
            hexdump(ciphertext, "Cipher text: ");
            cout << " --- " << endl;
            cout << "Cipher bytes: ";
            for (int i = 0; i < ciphertext.size(); i++) {
                printf("%d ", ciphertext.data()[i]);
            }
            cout << endl;
            cout << " --- " << endl;
            show_onece = true;
        }

        Message decrypted = decryption_session.decrypt( ciphertext );

        fatal_assert( decrypted.nonce.val() == nonce_int );
        fatal_assert( decrypted.text == plaintext );

        nonce_int++;
        if ( ! ( prng.uint8() % 16 ) ) {
            test_bad_decrypt( decryption_session );
        }
    }
    cout << "encrypt/decrypt test success." << endl;
}
