#include <iostream>
#include <sstream>
#include <stdio.h>
#include <cassert>
#include "select.h"

#define STDIN_FILENO 0

using namespace std;

int main(int argc, const char** argv) {
    /* prepare to poll for events */
    Select &sel = Select::get_instance();

    sel.read(STDIN_FILENO);

    cout << "Output." << endl;
}
