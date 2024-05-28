# mmTLS
mmTLS is a highly scalable TLS middlebox for monitoring encrypted traffic.

# Middlebox
For the TLS middlebox, we use DPDK 22.11, which use pkg-config. For building DPDK, please refer DPDK website and install.
After installing DPDK, the underlying library, mOS should be compiled. Run below.

```Bash
cd mmTLS/proxies/mOS
./setup.sh --compile-dpdk
```

Since we add more features to mOS for mmTLS, you should use our new mOS, not original mOS.

After building mOS, mmTLS apps can be compiled on mOS. We provide two sample apps; my_ips, my_cipherstat
my_ips is a simple IPS that read all the decrypted traffic and can do pattern-matching using snort-ruleset using hyperscan.
We first use it for microbenchmarks which does not require pattern matching. So the macro, HYPERSCAN is initially set as zero, but you can turn it on later.
my_cipherstat is a simple app to collect TLS information of Alexa top 1K web sites. We will use it later.

Before building mmTLS apps, make sure hyperscan library is installed.

```Bash
sudo apt install libhyperscan-dev
```

To compile my_ips and my_cipherstat, run below.

```Bash
cd mmTLS
make -j
```

Now check that you have my_ips and my_cipherstat on the same directory.

Before run my_ips, make sure you set enough hugepage.
Run below as sudo user.
```
echo 128 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
```
We use 1GB hugepage here, but you may use 2MB hugepage. If so, adjust the number of hugepages much larger.

Now adjust the configuration file of mmTLS, mmTLS/proxies/mOS/mmTLS/config/mos.conf.
If you want to use less than 16 cores, modify the CPU masks of each interface. (e.g., ens7f0np0 0xffff --> ens7f0np0 0x0001 for single core)

Run my_ips for microbenchmarks. -c option means the number of worker cores.

```Bash
sudo ./my_ips -c 16
```


# Key server
After running my_ips on mmTLS, you should run key server which receives session keys via out-of-band TLS channel from clients and distributes them to worker cores.
We provide two options for key server. First one is using SoC SmartNIC, and another one is using dedicated host core.
In this document, we introduce the first option.

We use Bluefield-2 for the SmartNIC. Make sure that you have installed rshim and can ssh to the Ubuntu server on Bluefield SoC.
Copy the key_server directory to the SmartNIC and ssh to it.
```Bash
scp -r key_server [yourID on SoC]@192.168.100.2:~/
ssh [yourID on SoC]@192.168.100.2
```

In our SmartNIC on our testbed, you can just login to it as below.

```Bash
# on junghan@box1.kaist.ac.kr
ssh junghan@192.168.100.2
```

Then, go to the copied directory and build.
```
cd key_server
make -j
```
Run the server. -c option specifies the number of cores used, and -i option specifies via which interface the key-server will send crafted UDP key packets.
Check your interface using ip link or ifconfig.
```
sudo ./key-server -c [num of cores used] -i [one of interface]
```

# Keysend library
Since mmTLS requires clients to share the E2E session keys, client programs should be recompiled to be linked with our key sharing library.
First copy the library to the client machine and do ssh.

```Bash
cd mmTLS
scp -r endpoints [yourID on client machine]@[client IP]:~/
ssh [yourID on client machine]@[client IP]
```

Before building nghttp2, ab, and chromium, go to mmTLS/endpoints/keysend directory and make a library for key sharing.

```Bash
cd endpoints/keysend
gcc -c keysend.o keysend.c
ar rcs libkeysend.a keysend.o
export KEYSEND_DIR=`pwd`
```

It will make a libkeysend.a library on endpoints/keysend/.
Then, copy the keysend.h header to /usr/local/include/ in order to make h2load and ab able to use this header.

```Bash
sudo cp keysend.h /usr/local/include/
```


# h2load
In this document, we only present a guide for h2load. We will add guides for other clients such as chromium later.
Download the nghttp2 repository from github, and go to your nghttp2 directory.

```Bash
cd nghttp2
```

Add below to somewhere in nghttp2/src/h2load.cc.

```Bash
#include <keysend.h>
```

Then, search SSL_CTX_set_keylog_callback, and modify that part. If you found lines like below,

```C
auto keylog_filename = getenv("SSLKEYLOGFILE");
if (keylog_filename) {
  keylog_file.open(keylog_filename, std::ios_base::app);
  if (keylog_file) {
    SSL_CTX_set_keylog_callback(ssl_ctx, keylog_callback);
  }
}
```

modify them as below.

```C
if (init_key_channel(ssl_ctx, config.nthreads) < 0)
  exit(EXIT_FAILURE);
SSL_CTX_set_keylog_callback(ssl_ctx, keysend_callback);
```

Search SSL_CTX_free, and add one more line before it.

```C
destroy_key_channel(ssl_ctx); // added line
SSL_CTX_free(ssl_cxt);
```

Now build mmTLS-ported h2load.
First, configure it to be linked with libkeysend.a. KEYSEND_DIR should be the path of libkeysend.a you compiled above.

```Bash
./configure LDFLAGS=$KEYSEND_DIR/libkeysend.a
make -j
```

You will have h2load on nghttp2/src directory.


# ab
To build httpd, make sure APR and PCRE are installed on your system. If not, run below.
```
sudo apt install libapr1-dev libaprutil1-dev libpcre3 libpcre3-dev
```
Then, go to httpd-2.4.54 directory and configure it to be linked with libkeysend.a. KEYSEND_DIR should be the path of libkeysend.a you compiled above.
Now you can build httpd including ab.

```Bash
cd httpd-2.4.54
./configure LDFLAGS=$KEYSEND_DIR/libkeysend.a
make -j
```

Now you have ab on httpd-2.4.54/support directory.


# Chromium
Building and linking chromium to keysend library is similar to the cases of h2load and ab.
However, building chromium from scratch takes so long time.
So, we have already prepared the binary of default chromium and mmTLS-ported chromium on one of our client machine, box2.kaist.ac.kr.
Both have a browser extension which measures page load time.


# Test
Before start testing, you should configure an address of the key server.
```
export KEYSERVERADDR=10.11.90.100
```

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
