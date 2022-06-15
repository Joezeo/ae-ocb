#ifndef FATAL_ASSERT_HPP
#define FATAL_ASSERT_HPP

#include <stdio.h>
#include <stdlib.h>

static void fatal_error( const char *expression, const char *file, int line, const char *function )
{
  fprintf( stderr, "Fatal assertion failure in function %s at %s:%d\nFailed test: %s\n",
           function, file, line, expression );
  abort();
}

#define fatal_assert(expr)						\
  ((expr)								\
   ? (void)0								\
   : fatal_error (#expr, __FILE__, __LINE__, __func__ ))

#endif
