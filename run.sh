#!/bin/bash
#DOCKER RUN COMMAND
docker run -d --net=host -e "DDNS=ddns.oakington.info" --name EmbyDDNS embyddns
