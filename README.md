# mmTLS

mmTLS is a highly scalable TLS middlebox for monitoring encrypted traffic.

<img style="width:1000px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/08e02f36-be13-443a-b923-3278b487c80f" />

mmTLS provides high throughput and low latency using techniques below.

1. Single connection architecture which removes redundant TLS/TCP handshakes, flow management, memory copies, and re-encryption
2. Scalable key distribution technique using SmartNIC or a dedicated core
3. Minimized overhead on private tag generation/verification
4. On-demand decryption of partial content via event-driven API



# Accessing remote machines for AE

Because Bluefield-2 SmartNIC is required for reproducing, we highly recommend you to run test scripts in our remote machines.
If you want to build and run on your own, please refer to INSTALL.md.

Currently we have a simple testbed to test functionality of our work, used for ATC’24 artifact evaluation. Please let us know (cerotyki@gmail.com or HotCRP) if you want to access to them.
Our testbed consists of 7 machines: 4 clients, 1 middlebox, and 2 backend servers. You can access to them via ssh. Please access to the access server first, and log in other 6 machines from the access server.

Access server is box3.kaist.ac.kr, and it is used as one of a backend server. A figure below depicts the topology of our testbed.

<img style="width:1000px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/7b82e7f2-834f-474c-9cad-c8b43e8ee3f1" />

This page assumes that you have an access to our machine, box3.kaist.ac.kr via ssh.

```Bash
ssh [guest ID]@box3.kaist.ac.kr
```

Then access to box1.kaist.ac.kr which has mmTLS middlebox source code.

```Bash
ssh box1.kaist.ac.kr
```

You should be able to see your home. Now export a mmTLS directory as a bash variable.

```Bash
cd mmTLS
export MMTLS_DIR=`pwd`
```



# nginx config as a baseline middlebox (Split-TLS) and endpoints

For your information, the configuration of nginx as a Split-TLS middlebox is as below. If you want to test various workload as you want. Use h2load or ab for those ports.
Note that svr0 and svr1 mean box3.kaist.ac.kr and box4.kaist.ac.kr, respectively.

```
	# LAN

	# endpoint:	0xxxx,	proxy to svr0: 	1xxxx,	proxy to svr1:	2xxxx
	# persistent: 	x0xxx, 	ephemeral: 	x1xxx,
	# TCP:		xx080, 	TLS12: 		xx442, 	TLS13:		xx443

	# 00080: endpoint persistent		TCP
	# 01080: endpoint ephemeral		TCP

	# 00442: endpoint persistent		TLS12
	# 01442: endpoint ephemeral		TLS12

	# 00443: endpoint persistent		TLS13
	# 01443: endpoint ephemeral		TLS13
	
	# 10080: proxy to svr0 persistent	TCP 
	# 11080: proxy to svr0 ephemeral	TCP

	# 10442: proxy to svr0 persistent	TLS12
	# 11442: proxy to svr0 ephemeral	TLS12

	# 10443: proxy to svr0 persistent	TLS13
	# 11443: proxy to svr0 ephemeral	TLS13

	# 20080: proxy to svr1 persistent	TCP
	# 21080: proxy to svr1 ephemeral	TCP

	# 20442: proxy to svr1 persistent	TLS12
	# 21442: proxy to svr1 ephemeral	TLS12

	# 20443: proxy to svr1 persistent	TLS13
	# 21443: proxy to svr1 ephemeral	TLS13


	# WAN

	# proxy to WAN:		3xxxx

	# 30443: proxy to usatoday		ephemeral	TLS13
	# 31443: proxy to bbc			ephemeral	TLS13
	# 32443: proxy to nytimes		ephemeral	TLS13
	# 33443: proxy to cnn			ephemeral	TLS13
	# 34443: proxy to washingtonpost	ephemeral	TLS13
```

The configuration of nginx as endpoints is a subset of above. Endpoints (box3, box4) use only upper 6 ports; 80, 1080, 442, 1442, 443, 1443.



# Figure 8 - mmTLS

You can run the middlebox on box1.kaist.ac.kr.
Log in to box1.kaist.ac.kr first.

```Bash
ssh box1.kaist.ac.kr
```

We prepared a pre-built mmTLS application which decrypts (and does DPI when -p option exists) the payload for the given size 
It is on mmTLS/proxies/mOS/mmTLS directory, so go to the that directory and run the sample application.

```Bash
cd mmTLS/proxies/mOS/mmTLS
sudo ./my_ips -c 16
```

When it starts to print the throughput logs, it is ready to work.
<img style="width:1000px;" src="https://github.com/TNET-SNU/mmTLS/assets/92782579/679cdfd6-0570-4ea0-9782-f4bb582bdcaa" />

Then, open a new ssh session to the middlebox machine (box1.kaist.ac.kr) and ssh to Bluefield-2 SmartNIC.
```Bash
ssh box1.kaist.ac.kr
```
```Bash
ssh 192.168.100.2 # on box1.kaist.ac.kr
```
Run the key-server on bf2_key_server directory.
```Bash
cd bf2_key_server
sudo ./key-server -c 8 -i p1
```
The key-server will prints the logs about secondary key channels.

Now, open one more new ssh session and go to the same directory.
Then, execute ./run-mmtls-clients-persistent-gcm.sh to run all four client machines at the same time.

```Bash
cd mmTLS/proxies/mOS/mmTLS
./run-mmtls-clients-persistent-gcm.sh 64k
```

64k means the clients request 64KB objects from the server. You can control it among 1k, 4k, 16k, 64k, 256k, 1m, 4m.
The output should seems like screenshot below.

<img style="width:1000px;" src="https://github.com/TNET-SNU/mmTLS/assets/92782579/c0919b1f-5056-4af6-9bc5-3489e3069513" />

With the printed logs, you can check the persistent throughput of mmTLS with ECDHE-RSA-AES-256-GCM-SHA384 on TLS 1.3.
After checking the throughput, you should stop the clients, as below.

```Bash
./stop-clients.sh
```
Then, stop the my_ips app by Ctrl+C.

You can also check DHE-RSA-AES-256-GCM-SHA256 with another script, run-mmtls-clients-persistent-cbc.sh.
Follow the same step above, but replace the script run-mmtls-clients-persistent-gcm.sh to run-mmtls-clients-persistent-cbc.sh as below.

```Bash
./run-mmtls-clients-persistent-cbc.sh 64k
```

Then, you will see the throughput with DHE-RSA-AES-256-GCM-SHA25 as logs from my_ips.
As same as ECDHE-RSA-AES-256-GCM-SHA384, after checking the throughput, stop the clients and my_ips.


# Figure 8 - split-TLS (nginx TLS proxy)
If you want to measure the throughput of split-TLS which is one of our baselines, you should stop my_ips and use nload on the middlebox.

```Bash
nload
```

You can see other interfaces using arrow keys (e.g., <-, ->).
nload prints the throughput of each interface in Gibps. So you should multiply 1.024 * 1.024 * 1.024 to the printed throughput.
[We have confirmed that the source code of nload is actually computing Gibps rather than Gbps.](https://github.com/rolandriegel/nload/blob/8f92dc04fad283abdd2a4538cd4c2093d957d9da/src/statistics.cpp#L125)
Or, you can check the bps by adding -u b option to nload.

```Bash
nload -u b
```

It will show the throughput in bps unit.
Since nginx TLS proxy is running on the middlebox machine as background by default, you do not need to execute any middlebox application here.

Now open a new ssh session to box1.kaist.ac.kr, and run the client script.

```Bash
cd mmTLS/proxies/mOS/mmTLS
./run-splittls-clients-persistent-gcm.sh 64k
```

Now, you can check the split-TLS throughput on logs of nload (first session).
After checking the throughput, you should stop the clients, as below.

```Bash
./stop-clients.sh
```

You can also check DHE-RSA-AES-256-GCM-SHA256 with another script, run-splittls-clients-persistent-cbc.sh.

```Bash
./run-splittls-clients-persistent-cbc.sh 64k
```

Then, you will see the throughput withDHE-RSA-AES-256-GCM-SHA256 as logs from nload.


# Figure 8 - mcTLS

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
The method is similar to the evaluation for figure 8.

You can run the middlebox on box1.kaist.ac.kr.
Log in to box1.kaist.ac.kr first.

```Bash
ssh box1.kaist.ac.kr
```

Then, go to the the directory including my_ips and run the sample application with **bf{single core}**.
In our testbed, 4 clients and 2 servers cannot make the middlebox bottleneck in ephemeral connections, since ephemeral connections incur huge overhead on endpoints.

```Bash
cd mmTLS/proxies/mOS/mmTLS
sudo ./my_ips -c 1
```

Then, do ssh to the SoC SmartNIC to run key-server.

```Bash
ssh 192.168.100.2
```
``` Bash
cd bf2_key_server
sudo ./key-server -c 8 -i p1
```

The key-server will print the logs; total key., 

Now, run ephemeral clients instead of persistent.

```Bash
./run-mmtls-clients-ephemeral-gcm.sh
```

Since we fix the size of requested objects as 1KB for ephemeral connections, the script does not need any parameter.


One thing different is that you should check the logs printed by the key-server running on SoC SmartNIC.
It will print the total keys, keys per second, total connections, connections per second. (In the context of key-server, connection means the secondary key channel, which are persistent.)
The second log, keys per second shows the E2E connections established in one second.

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
Note that this script modifies the default routing table entry to make the WAN traffic comes and goes via LAN (private network) interface instead of default WAN (public network) interface.
(Unless, WAN traffic will not goes to the middlebox which is connected via LAN interface.)
If you are accessing via ssh to WAN interface of the client (wood1), your ssh session will be lost.
Please do ssh from the access point machine (box3), and run the script.

Since the news site is updated every hour, the result will be differenct with our evaluation.
We recommend you to check the gap between mmTLS and split-TLS, rather than the absolute response time of mmTLS.

Also, www.washingtonpost.com no longer supports http/1.1. It currently accepts only http/2.
But, the nginx proxy (split-TLS) currently supports up to http/1.1 as backend upstream connection, so we could not fully reproduce the result of split-TLS.
So, the result for split-TLS to washingtonpost will appear empty.
If you think the absolute response time is necessary, please let us know. We will prepare other popular web sites to test split-TLS to WAN.


# Figure 13a
Same as figure 8. Just run my_ips app with -c 1, 2, 4, 8, and 16.

```Bash
cd mmTLS/proxies/mOS/mmTLS
sudo ./my_ips -c 1 # single core
```

Run the clients to request 64KB objects.

```Bash
./run-h2load-persistent.sh 64k
```

Then, check the throughput log printed by my_ips.


# Figure 13b
Since the throughput of mmTLS middlebox is already measured by evaluation for figure 8, it is enough to measure the throughput of an endpoint TLS server.
Stop all the middlebox program on the middlebox machine (box1.kaist.ac.kr), and run the clients.

```Bash
./run-h2load-persistent.sh [file size]
```

You should run the test for file size 1k, 4k, 16k, 64k, 256k, 1m, and 4m.
Check the printed throughput by nload.


# Figure 14
1. Run below. It generates the TLS record tag in 4 ways. 1. Original (no private tag) 2. mmTLS (optimal) 3. Reusing ciphertext 4. Double tags (naive)

```Bash
cd $MMTLS_DIR/openssl-modified/tag-gen
./tag
```

It will take about 1 minute, and the printed result will be equivalent to the figure 14.


# Figure 15


# Figure 16
Run my_ips app with option -p and -l on the middlebox machine (box1.kaist.ac.kr).

```Bash
cd mmTLS/proxies/mOS/mmTLS
sudo ./my_ips -c 16 -p -l 16 # DPI on first 16KB
```

Then start the clients using run-h2load-persistent.sh.

```Bash
./run-h2load-persistent.sh 1m
```

my_ips app will prints the real-time throughput.

To run split-TLS DPI, use the pre-built binaries, nginx-dpi-16k, nginx-dpi-32k, nginx-dpi-64k, and nginx-dpi-128k on nginx-1.24.0 directory at the middlebox machine (box1.kaist.ac.kr).

```Bash
cd nginx-1.24.0
sudo ./nginx-dpi-16k -c /etc/nginx/16.conf # replace the binary as you want
```

Then measure the throughput using nload on the middlebox machine (box1.kaist.ac.kr).
Do not forget multiplying 1.024 * 1.024 * 1.024 to the printed nload log.


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
