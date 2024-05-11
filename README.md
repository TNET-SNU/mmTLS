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
You can run the middlebox on box1.kaist.ac.kr.
Log in to box1.kaist.ac.kr first.
```Bash
ssh box1.kaist.ac.kr
```
Go to the my_ips directory, and run the middlebox.
```Bash
cd mmTLS/proxies/mOS/mmTLS
sudo ./my_ips -c 16
```
When it starts to print the throughput logs, it is ready to work.
Run the client machines at once. You can use our script that runs 4 clients at once.
Open new ssh session and go to the same directory.
```Bash
cd mmTLS/proxies/mOS/mmTLS
./run-h2load-persistent 64k
```
You can check the throughput of mmTLS on the first ssh session.
Adjust the number of cores as you want.

To check the baselines, you should stop my_ips and use nload on the middlebox.
```Bash
nload
```
You can see other interfaces using arrow keys (e.g., <-, ->).
nload prints the throughput of each interface in Gibps. So you should multiply 1.024 * 1.024 * 1.024 to the printed throughput.
(Search the source code of nload at github and check that it actually uses Gibps, while the printed units are Gbps.)

Now open new ssh session to box1.kaist.ac.kr, and run the client script.
```Bash
cd mmTLS/proxies/mOS/mmTLS
./run-h2load-persistent.sh 64k
```
Now, you can check the split-TLS throughput.

To see the throughput of mcTLS, run mcTLS server on box3.kaist.ac.kr first.
```Bash
cd ~/mctls/evaluation/client_server
./wserver -c spp_mod -o 3 > /dev/null 2> /dev/null &
```
Then, run mcTLS mbox on another ssh session to box1.kaist.ac.kr.
```Bash
cd ~/mctls/evaluation/client_server
./mbox -c spp_mod -a 10.11.90.3:4433 -m 10.11.90.1:8423 > /dev/null 2> /dev/null &
```
At last, run mcTLS clients at once using the script on box1.kaist.ac.kr.
```Bash
cd ~/mctls/evaluation/client_server
./run-mctls-client-persistent.sh 64k
```
Now, you can check the mcTLS throughput using nload on box1.kaist.ac.kr.

# Figure 9
The flow is similar to the fig8.
Run ephemeral clients instead of persistent.

# Figure 10

# Figure 11 & Figure 12
We measure the LAN response time for 100 times and get the average, and measure the WAN response time for 200 times and get the average of 25% ~ 75%, since WAN connection is very unstable.
To simplify your evaluation, we prepared a simple all-in-one script on the client side.
Log in to wood1.kaist.ac.kr first.
```
ssh wood1.kaist.ac.kr
```
Since our script includes running the mmTLS or mcTLS (baseline) middlebox on box1.kaist.ac.kr as background program, you don't need to directly control the middlebox.
Move to the fig11 directory and run all-in-one script. It takes about 5 minutes.
```
cd ~/fig11
./kill-others.sh # When something goes wrong, run kill-others.sh and restart.
./all-in-one.sh
```
The result will be equivalent to figure 11 for both 11(a) -GCM- and 11(b) -CBC-.

For figure 12, we prepared a simple all-in-one script on the client side as well as fig 11.
```
cd ~/fig12
./kill-others.sh
./all-in-one.sh
```
It will take about 10 minutes.

Since the news site is updated every hour, the result will be differenct with our evaluation.
Also, www.washingtonpost.com currently does not support http/1.1, so we could not reproduce the result of split-TLS. The result for it will be empty.
In this figure, please check that mmTLS is similar to E2E-TLS, while split-TLS increases the response time for WAN connections.

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
