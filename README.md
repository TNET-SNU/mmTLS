# mmTLS
mmTLS is a highly scalable TLS middlebox for monitoring encrypted traffic.

# Middlebox
For the TLS middlebox, we use DPDK 22.11, which use pkg-config. For building DPDK, please refer DPDK website and install.
After installing DPDK, the underlying library, mOS should be compiled. Run below.

```
cd mmTLS/proxies/mOS
./setup.sh --compile-dpdk
```

(Since we add more features to mOS for mmTLS, you should use our new mOS, not original mOS.)

After building mOS, mmTLS apps can be compiled on mOS. We provide two sample apps; my_ips, my_cipherstat
my_ips is a simple IPS that read all the decrypted traffic and can do pattern-matching using snort-ruleset using hyperscan.
We first use it for microbenchmarks which does not require pattern matching. So the macro, HYPERSCAN is initially set as zero, but you can turn it on later.
my_cipherstat is a simple app to collect TLS information of Alexa top 1K web sites. We will use it later.

Before building mmTLS apps, make sure hyperscap library is installed.
```
sudo apt install libhyperscan-dev
```

To compile my_ips and my_cipherstat, run below.

```
cd mmTLS
make -j
```

Now check that you have my_ips and my_cipherstat on the same directory.

Before run my_ips, make sure you set enough hugepage. (We have already set enough amount of hugepage for our remote machine. So if you evaluate on our machine, do not care about it.)
Run below as sudo user.
```
echo 128 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
```

We use 1GB hugepage here, but you may use 2MB hugepage. If so, adjust the number of hugepages much larger.

Now adjust the configuration file of mmTLS, mmTLS/proxies/mOS/mmTLS/config/mos.conf.
If you want to use less than 16 cores, modify the CPU masks of each interface. (e.g., ens7f0np0 0xffff --> ens7f0np0 0x0001 for single core)

Run my_ips for microbenchmarks. -c option means the number of worker cores.
```
./my_ips -c 16
```

# Key server
After running my_ips on mmTLS, you should run key server which receives session keys via out-of-band TLS channel from clients and distributes them to worker cores.
We provide two options for key server, first is using SoC SmartNIC. We use Bluefield-2 for the SmartNIC.

Log in to the Ubuntu server on Bluefield SoC by below command.
(If you are running on your own machine with bluefield, make sure that you have installed rshim.)
```
ssh junghan@192.168.100.2
```

Then, you can see a directory, bf2_key_server on home. Just run below to run the key server on BF2.
```
cd bf2_key_server
make -j
./key-server -c 8 -i p1
```


# h2load and ab
Since mmTLS requires clients to share the E2E session keys, client programs should be recompiled to be linked with our key sharing library.
In this repository, we provide how to make mmTLS-ported versions of chromium browser, h2load load tester in nghttp2, and ab load tester in Apache httpd.

Before building nghttp2, run below on nghttp2 directory to make a library for key sharing.
```
gcc -c keysend.o keysend.c
ar rcs libkeysend.a keysend.o
```
It will make a libkeysend.a library on nghttp2 directory. Now run below to link h2load with the keysend library.
```
cd nghttp2
export KEYSEND_DIR=`pwd`
./configure LDFLAGS=$KEYSEND_DIR/libkeysend.a
make -j
```
Now you have h2load on nghttp2/src directory. After building h2load, build ab on httpd-2.4.54 directory.
To build httpd, make sure APR is installed on your system. If not, run below.

```
sudo apt-get install libapr1-dev libaprutil1-dev
```
Now you can build httpd including ab.
```
cd httpd-2.4.54
./configure LDFLAGS=$KEYSEND_DIR/libkeysend.a
make -j
```
Now you have ab on httpd-2.4.54/support directory.

To start ephemeral connections test, run below on home.
```
./short_conn_test.sh 10.11.90.3 1k 1024 -j
```
-j option enables key sharing in ab.

To start persistent connections test, run below on home.
```
nghttp2/src/h2load -c1024 -n10240000 -t16 https://10.11.90.3/1m/test0 --key-send
```
--key-send option enables key sharing in h2load.

# Chromium

(...)


# OpenSSL with mmTLS
You can also check the microbenchmark result for private tag generation. Run below to reproduce the result.
```
cd openssl-modified/tag-gen
make -j
./tag
```

It will print the relative overhead of 1. original TLS, 2. mmTLS, 3. Reusing ciphertext, 4. Double tags.

If you want to check the performance of nginx server with mmTLS, you should build openssl with MMTLS macro in openssl-modified/include/openssl/macros.h like below.
```
#define MMTLS 1
```
We already have set the macro as 1, and built the OpenSSL and nginx. If you are working on our remote machine, you do not need to rebuild both.
If you are working on your own machine, you need to re-build the nginx.
```
cd nginx-modified
./configure --prefix=. --with-openssl=../openssl-modified --with-http_ssl_module
make -j
cp objs/nginx nginx
sudo ./nginx -c /etc/nginx/nginx.conf
```
If you are running nginx on your own machine, use your own nginx.conf file instead.


# DPI applications
For testing DPI application on mmTLS, run my_ips with -p option. Also, you can set how many bytes to DPI by -l option. -l option is in unit of KB, so if you want to do DPI the first 64KB, use -l 64.
```
./my_ips -c 16 -p -l 64
```

For testing DPI application on split-TLS, modify the HYPERSCAN macro to positive value. It is in nginx-modified/src/core/ngx_config.h.
```
#define HYPERSCAN 64
```
After modifying HYPERSCAN macro, re-build the nginx. The nginx will do DPI the first 64KB of HTTP response.
You can adjust the length for DPI by modifying HYPERSCAN macro.

For your convenience, we have already built 4 nginx binaries. They are for 16K DPI, 32K DPI, 64K DPI, 128K DPI, respectively.
If you want to test them, run below after re-building.
```
make -j
cp objs/nginx nginx-dpi-16k
./sudo nginx-dpi-16k -c /etc/nginx/nginx.conf
```
You can run nginx-dpi-32k, nginx-dpi-64k, nginx-dpi-128k as well. Before running new nginx, stop or kill the existing nginx daemon to make new nginx daemon able to bind ports.
```
sudo killall nginx*
```
