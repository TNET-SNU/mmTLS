# mmTLS
mmTLS is a highly scalable TLS middlebox for monitoring encrypted traffic.

Because Bluefield-2 SmartNIC is required for reproducing, we highly recommend you to run test scripts in our remote machines.
If you want to build and run on your own, please refer to INSTALL.md.
This page assumes that you have an access to our machine, box1.kaist.ac.kr via ssh.
Go to kvpn.kaist.ac.kr, and follow the instruction. You can log in to Ivanti VPN using a temporary account, cerotyki.

After applying kvpn, run below on your local machine to log in.
```Bash
ssh guest@box1.kaist.ac.kr
```
You should be able to see your home. Now export a mmTLS directory as a bash variable.
```Bash
cd mmTLS
export MMTLS_DIR=`pwd`
```

# Figure 8

# Figure 9

# Figure 10

# Figure 11

# Figure 12

# Figure 13a

# Figure 13b

# Figure 14
1. Run below. It generates the TLS record tag in 4 ways. 1. Original (no private tag) 2. mmTLS (optimal) 3. Reusing ciphertext 4. Double tags (naive)
```Bash
cd $MMTLS_DIR/openssl-modified/tag-gen
./tag
```
It will take about 1 minute, and the printed result will be equivalent to the figure 14.

# Figure 15

# Figure 16

# Figure 17
1. Run mmTLS middlebox first.
```Bash
cd $MMTLS_DIR/proxies/mOS/mmTLS
sudo ./my_cipherstat -c 1
```

2. Log in to the client machine.
```Bash
ssh wood1.kaist.ac.kr
```

3. Run cipherstat.sh
```Bash
./cipherstat.sh alexa
```
It will take about 10 minutes.

4. After running above, stop the middlebox and see the alexa file on the mmTLS directory.

The result will be equivalent to the figure 17.
