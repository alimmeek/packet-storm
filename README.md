# PACKET STORM

A challenge ran by Coretech to develop a high-speed program in C, C++ or Rust to process an intercepted 1,000,000 packet capture (.pcap) file.

## Pre-requisites
* libpcap
* libpthread

## Running
Download/clone repo and `cd` into `packet-storm`. The next step depends on what OS you're running on:

### UNIX-based systems
In the terminal, run:
> ./run.sh

This will set an environment variable `NUM_PROC` as the result of the command `nproc`, compile the codebase and run it.

### Other systems
You'll need to set `NUM_PROC` manually as the number of processors available on your machine.

Once you've done that:
> make
> 
> ./build/packet-storm
