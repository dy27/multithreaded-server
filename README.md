# multithreaded-server

## Overview
A multithreaded networking server in C which supports file retrievals and other queries.

## Features
- Multiplexed file transfer, which enables a client to request a single file split over multiple parallel connections to increase the speed of file transfer.
- File compression: the client can request for files to be compressed before transfer. A bitwise compression/decompression algorithm is implemented using Huffman coding.
- Multithreading using a thread pool. This allows multiple clients to be serviced simultaneously. Synchronisation between threads is achieved by using a thread-safe work queue. The server can be initialised with any number of threads.
