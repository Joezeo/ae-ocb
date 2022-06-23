#include "select.h"

fd_set Select::dummy_fd_set;

sigset_t Select::dummy_sigset;

unsigned int Select::verbose = 0;

void Select::handle_signal( int signum )
{
  fatal_assert( signum >= 0 );
  fatal_assert( signum <= MAX_SIGNAL_NUMBER );

  Select &sel = get_instance();
  sel.got_signal[ signum ] = 1;
}

