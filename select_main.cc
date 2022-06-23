#include <iostream>
#include <sstream>
#include <stdio.h>
#include <cassert>
#include <unistd.h>
#include "select.h"

// #define STDIN_FILENO 0

using namespace std;

int main(int argc, const char** argv) {
    /* prepare to poll for events */
    Select &sel = Select::get_instance();
    sel.add_signal(SIGWINCH);
    sel.add_signal(SIGTERM);
    sel.add_signal(SIGINT);
    sel.add_signal(SIGHUP);
    sel.add_signal(SIGPIPE);
    sel.add_signal(SIGCONT);

    sel.read(STDIN_FILENO);

    cout << "Output." << endl;
}
