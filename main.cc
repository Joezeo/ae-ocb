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

    // char *cons = new char[146] {-128, 0, 0, 0, 0, 0, 0, 0, 53, 86, 32, 61, 120, 114, 66, 52, 38, -25, 52, 49, 79, 65, -44, 87, 107, -30, -9, -46, -65, 57, 9, -107, -14, -81, 86, -79, -65, 31, 70, -60, -41, 24, 15, 78, -99, -55, 79, 7, 81, 57, 2, -56, 4, -107, 120, 9, 109, -117, 52, 47, 54, -86, 70, 80, 30, 58, 12, -14, 18, -90, 50, 115, 24, -92, -15, -57, 54, -12, 50, -100, -85, -71, 44, -39, -51, -44, 52, 34, 82, -64, -27, 72, 8, 49, 15, -39, -58, 36, -61, -3, -94, 6, -38, -3, -50, 36, -71, -116, 13, -113, -78, 52, -6, -32, 35, -90, -83, 109, -114, 75, -101, -34, 102, 41, 40, 103, 69, 32, -80, -92, -84, -13, 25, -107, 114, 20, 92, -83, 20, 69, -75, -71, 15, 51, 32, 30};
    char *cons = new char[1091] {-39, -105, 5, 68, 56, -66, 62, -69, -42, 0, 21, 68, -25, 122, 33, 31, -53, -90, -52, 52, -43, -125, -102, 83, 32, 46, -110, 24, 103, 73, 54, 7, -122, -67, 47, 97, -117, 96, 71, 116, 0, -10, 44, -100, 61, -42, 56, -7, 117, 17, 115, -4, 80, -124, -35, -66, 64, 5, -118, 96, -83, 115, -45, 99, 99, -37, 120, 113, 91, 118, 2, 88, -121, -48, 122, -83, -56, -33, -66, 16, 77, 92, -92, -9, -81, -44, 94, -19, 60, -17, 77, 28, 29, -90, -93, 45, -31, -90, -63, 13, 52, 123, 24, -70, 11, -86, -22, 31, 81, 70, -95, -46, 36, -14, 34, 1, 10, -109, 44, 63, 7, 103, 109, 40, 43, 111, -5, 28, 33, -74, -32, 79, 67, 75, 0, -55, -92, 89, -66, -6, -113, -65, 64, 110, -110, -98, 73, 95, -14, -18, 62, -97, -98, -10, 1, 51, -53, -107, 84, 56, 26, 54, 75, 114, -94, 7, -45, -13, 0, 123, -93, -59, 66, -92, 52, -41, 36, -86, -49, 72, 92, 8, 95, -113, 5, -7, -79, 83, 38, 58, 21, 111, -94, -12, 55, 55, -29, -114, -19, -90, 56, 13, -71, 3, 23, 69, -116, -30, -68, 35, 71, -115, 66, 28, 90, -19, 105, 47, -87, -11, -97, 34, 122, 18, -26, -37, 66, 30, -121, -93, 1, 78, -41, -49, -90, 7, -117, 65, 92, -113, -71, 48, 25, -98, 72, -30, -81, -28, -106, 89, -104, -77, -78, -38, -43, 51, 44, -35, 11, -86, -23, -27, 2, -56, 45, -66, 58, -28, 93, -72, 38, -71, -33, -66, -106, 103, -70, -104, 89, 37, 8, 116, -55, -65, 104, 40, 99, 19, -48, 59, 10, -49, 100, -81, -52, 74, 58, -11, 89, 48, 86, -65, -8, 51, 24, 20, -108, 34, -73, 13, -119, 123, 61, -37, -37, 89, -102, 57, -38, 12, -12, 90, 80, 96, -118, 18, 115, -60, -24, 121, -8, -29, 6, -96, 29, -118, -12, -103, 127, 14, -118, -52, -122, -20, 67, 103, -18, -15, 107, -70, 58, -123, -47, 35, 65, 42, -96, -19, 122, -62, 127, 89, -52, -90, -61, 37, -113, 87, -109, -94, -11, 33, 79, 6, -117, -86, 113, 78, -64, -51, 80, 41, -106, -4, 35, 126, 104, -89, -21, 73, -100, -54, -89, 1, -113, 76, 122, -96, -31, -61, -92, 84, -60, 77, -44, -15, -53, -97, 9, -87, -107, -65, -36, 111, -76, 87, 72, -94, 101, 102, 88, -27, 31, -124, 2, -23, 78, 12, 81, 95, -34, -23, -100, -43, -57, -70, 97, 107, -111, -8, 120, 74, 87, -99, -49, -43, -15, 5, -41, 9, 111, 112, 76, 34, 95, 102, -80, -68, -118, -51, 91, 6, 67, 73, -105, 73, 18, 99, 125, 14, 118, -114, 41, -34, -116, 29, -51, 59, -24, 83, -118, -68, 24, 67, 1, 53, 74, -84, 70, 82, 37, 108, -63, -121, -106, 27, -57, 105, -47, 127, 51, -97, 93, -38, -21, 101, -124, -85, 27, 19, -20, -115, 105, -5, -19, 39, -5, 22, -48, 110, 34, 54, 68, -104, -116, 12, -91, 101, -50, 33, -115, 73, 49, 87, 60, 102, 94, 38, -3, -81, -62, 120, -121, -46, 69, 124, 16, 47, 112, 16, 94, 87, -6, -92, -81, -99, 60, 60, -112, 31, 18, -115, 108, 3, 90, -41, -116, -85, -124, -113, 34, 48, 69, -88, -6, 7, 54, 20, 54, 52, 74, 4, -67, 98, 16, -41, -58, 41, 14, 35, -30, -38, 99, 1, 97, 47, -50, -122, 20, 63, -100, -4, 55, 90, -44, 98, 32, 44, 113, 70, -86, -57, -119, 113, -2, 26, -105, -53, 111, -50, 122, -64, 97, 97, -17, -14, -31, -53, 47, -47, -40, 86, 16, -117, -116, -99, -26, -89, 30, 107, 109, -81, -48, 17, 23, -116, 69, -73, 32, 102, 108, -87, -54, -45, -35, 41, -40, -26, -77, -71, 32, 106, 66, 108, 56, -46, 119, 90, -112, -56, 49, -90, 13, 13, 10, 64, 94, 41, -29, -42, -117, 84, 79, -86, -57, -85, -49, 65, 24, 32, 73, -124, 73, -99, 3, -56, -6, 49, -22, -26, -28, -117, -90, -116, -124, 114, -118, -82, 41, -38, -117, -98, 109, -105, 82, 82, -22, -15, -100, 53, -23, 117, 22, 105, -62, 47, -84, -109, 113, 127, 90, -97, 48, -44, 78, -63, 17, 100, -11, -55, -20, 124, 66, -118, -85, -73, 30, 120, -35, -114, 100, -51, -125, -24, -12, 35, -37, 32, -89, -86, -128, -22, -89, 106, -70, 20, 105, -69, 115, 92, -40, 124, 126, 49, 90, -85, 11, -109, 111, -27, 85, -99, -48, 46, 64, 114, 53, 48, 21, 15, 34, -26, 76, -29, -39, -11, -3, -82, 70, 59, 41, -56, 49, -23, -29, 34, -113, 120, -6, -102, 65, -83, 26, 31, 121, -14, 95, -63, -75, 32, -128, 48, 126, -77, 42, 80, 18, -108, 42, 100, -53, -122, -112, -109, -13, 50, -25, -33, 45, 13, -94, -44, 26, -11, -31, -50, 103, -46, 18, 82, -2, 17, -15, 23, -49, 28, 117, -2, 89, -69, -115, -53, 61, -95, -7, 88, 115, 93, 95, -22, -107, 110, 64, 125, -80, 51, -108, 6, 24, -65, -17, 70, -67, -120, -76, -39, -49, -56, -123, 14, 13, 17, -99, -54, 60, -27, 69, 80, -98, 77, 94, -95, 29, 66, -70, -119, 23, 108, 83, 34, 122, -55, -50, 51, -90, 31, -108, 4, 119, -5, -64, 18, -73, -54, 80, 109, 24, -35, 94, 15, -55, 48, 116, 117, -84, -20, -20, -105, 72, -122, -21, -7, -48, -9, 111, -107, 101, 34, -82, -53, -79, 91, 52, -23, -19, -83, 63, -107, -97, 110, -95, 74, 38, -69, -7, 107, -116, 112, 100, -115, 69, 25, 14, -40, 17, 58, 73, 71, -4, -86, 116, 58, 62, 94, -13, 106, 93, 85, -67, -34, -82, -117, -112, -102, 105, 107, 76, 16, 118, -2, 7, -55, 81, 112, -49, -36, 81, -99, 117, 48, -88, 117, -39, 102, 17, 65, -118, 44, -26, 104, 63, -58, -33, -109, -11, -17, 121, 13, -11, -3, 90, 68, 23, 23, 28, 109, 9, 62, -63, 122, -82, -11, -105, 89, -112, -4, -98, -101, -36, -97, -114, 20, 121, -49, -93, -22, -103, -60, 74, 72, 78, -27, 61, -29, -4, -58, -26, -17, 120, -119, 6, 25, -99, -125, 45, 16, 59, 8, 84, 87, 82, 106, -41, -47, 27, 115, -79, -46, 110, 87, 41 };
    string src(cons, 1091);
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
    /*
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
    */
}
