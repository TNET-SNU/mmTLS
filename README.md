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


# Clients
Since mmTLS requires clients to share the E2E session keys, client programs should be recompiled to be linked with our key sharing library.
In this repository, we provide how to make mmTLS-ported versions of chromium browser, h2load load tester in nghttp2, and ab load tester in Apache httpd.


(...)

