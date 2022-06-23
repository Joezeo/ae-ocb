#include "config.h"

#include "timestamp.h"

#include <errno.h>

#if HAVE_CLOCK_GETTIME
#include <time.h>
#endif
#if HAVE_MACH_ABSOLUTE_TIME
#include <mach/error.h>
#include <mach/mach_time.h>
#endif
#if HAVE_GETTIMEOFDAY
#include <sys/time.h>
#include <stdio.h>
#endif

// On Apple systems CLOCK_MONOTONIC is unfortunately able to go
// backwards in time. This breaks mosh when system is returning from
// suspend as described in ticket #1014. To avoid this issue prefer
// CLOCK_MONOTONIC_RAW on Apple systems when available.
#if defined(__APPLE__) && defined(CLOCK_MONOTONIC_RAW)
#define CLOCKTYPE CLOCK_MONOTONIC_RAW
#else
#define CLOCKTYPE CLOCK_MONOTONIC
#endif

static uint64_t millis_cache = -1;

uint64_t frozen_timestamp( void )
{
  if ( millis_cache == uint64_t( -1 ) ) {
    freeze_timestamp();
  }

  return millis_cache;
}

void freeze_timestamp( void )
{
  // Try all our clock sources till we get something.  This could
  // break if a source only sometimes works in a given process.
#if HAVE_CLOCK_GETTIME
  // Preferred clock source-- portable, monotonic, (should be)
  // adjusted after system sleep
  struct timespec tp;

  if (
#if defined(__APPLE__) && defined(__MACH__)
      // Check for presence, for OS X SDK >= 10.12 and runtime < 10.12
      &clock_gettime != NULL &&
#endif
      clock_gettime( CLOCKTYPE, &tp ) == 0 ) {
    uint64_t millis = tp.tv_nsec / 1000000;
    millis += uint64_t( tp.tv_sec ) * 1000;

    millis_cache = millis;
    return;
  }
#endif
#if HAVE_MACH_ABSOLUTE_TIME
  // Monotonic, not adjusted after system sleep.  OS X 10.12 has
  // mach_continuous_time(), but also has clock_gettime().
  static mach_timebase_info_data_t s_timebase_info;
  static double absolute_to_millis = 0.0;

  if (absolute_to_millis == 0.0) {
    if (ERR_SUCCESS == mach_timebase_info(&s_timebase_info)) {
      absolute_to_millis = 1e-6 * s_timebase_info.numer / s_timebase_info.denom;
    } else
      absolute_to_millis = -1.0;
  }

  // NB: mach_absolute_time() returns "absolute time units"
  // We need to apply a conversion to get milliseconds.
  if (absolute_to_millis > 0.0) {
    millis_cache = mach_absolute_time() * absolute_to_millis;
    return;
  }
#endif
#if HAVE_GETTIMEOFDAY
  // Not monotonic.
  // NOTE: If time steps backwards, timeouts may be confused.
  struct timeval tv;
  if ( gettimeofday(&tv, NULL) ) {
    perror( "gettimeofday" );
  } else {
    uint64_t millis = tv.tv_usec / 1000;
    millis += uint64_t( tv.tv_sec ) * 1000;

    millis_cache = millis;
    return;
  }
#else
# error "gettimeofday() unavailable-- required as timer of last resort"
#endif
}

