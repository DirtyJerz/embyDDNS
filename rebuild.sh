#!/bin/bash
docker rm -f EmbyDDNS
#docker rmi embyddns
./build.sh
./run.sh
./chroot.sh
