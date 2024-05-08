#!/bin/bash

sudo killall nginx-partial-dpi
make -j
cp objs/nginx nginx-partial-dpi
sudo ./nginx-partial-dpi -c /etc/nginx/nginx.conf
