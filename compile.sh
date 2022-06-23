#!/bin/bash

TYPE=$1;
if [[ $TYPE == 1 ]]
then
    g++ ae_ocb.cc -I/home/toocol/Downloads/boost_1_79_0 -L/home/toocol/Downloads/boost_1_79_0/stage/lib -L/usr/lib/x86_64-linux-gnu/libssl.so -lssl -lcrypto -o run ;
elif [[ $TYPE == 2 ]]
then
    g++ ocb.cc base64.cc crypto.cc main.cc -L/usr/lib/x86_64-linux-gnu/libssl.so -lssl -lcrypto -o run ;
elif [[ $TYPE == 3 ]]
then
    g++ select.cc timestamp.cc select_main.cc -o run ;
else 
    echo 'Please input compile type: [1] to complie ae_ocb.cc, [2] to complie main.cc, [3] to compile select_main.cc';
fi
