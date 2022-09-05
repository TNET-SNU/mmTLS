#!/bin/sh

taskset -c 0 h2load -n 6400 -c 64 https://10.1.95.14/1m &
taskset -c 1 h2load -n 6400 -c 64 https://10.1.95.14/1m &
taskset -c 2 h2load -n 6400 -c 64 https://10.1.95.14/1m &
taskset -c 3 h2load -n 6400 -c 64 https://10.1.95.14/1m &
taskset -c 4 h2load -n 6400 -c 64 https://10.1.95.14/1m &
taskset -c 5 h2load -n 6400 -c 64 https://10.1.95.14/1m &
taskset -c 6 h2load -n 6400 -c 64 https://10.1.95.14/1m &
taskset -c 7 h2load -n 6400 -c 64 https://10.1.95.14/1m
