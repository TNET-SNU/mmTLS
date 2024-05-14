# mmTLS

mmTLS is a highly scalable TLS middlebox for monitoring encrypted traffic.

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/08e02f36-be13-443a-b923-3278b487c80f" />

mmTLS  achieves high throughput and low latency leveraging the techniques below.

1. Single connection architecture which removes redundant TLS/TCP handshakes, flow management, memory copies, and re-encryption
2. Scalable key distribution via SmartNIC (or a dedicated CPU core)
3. Minimal overhead on private tag generation/verification
4. Support for event-driven API for programming TLS connections




# Accessing machines remotely for AE

mmTLS currently leverages the Bluefield-2 SmartNIC, so we recommend accessing our test machine with the SmartNIC from remotely and running test scripts on them.
If you want to build and run the system on your own, please refer to INSTALL.md.
We have set up a simple testbed to evaluate the functionality of our work, used for ATC’24 artifact evaluation.
Please let us know (cerotyki@gmail.com or HotCRP) and we will provide the credential to login to the test machine.
Our testbed consists of 7 machines: 4 clients, 1 middlebox, and 2 backend servers (see the picture below) and all of them are accessible by ssh.
Please log into the access server (i.e., box3.kaist.ac.kr) first, and you can log into other machines from it.
The figure below depicts the topology of our testbed.

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/7b82e7f2-834f-474c-9cad-c8b43e8ee3f1" />

This page assumes that you have access to box3.kaist.ac.kr via ssh.

```Bash
ssh [guest ID]@box3.kaist.ac.kr
```

Then log into box1.kaist.ac.kr which has the mmTLS middlebox source code.

```Bash
ssh box1.kaist.ac.kr
```

Enter “mmTLS” directory from the home directory, and export the mmTLS directory path as a bash variable.

```Bash
cd mmTLS
export MMTLS_DIR=`pwd`
```



# Configuring nginx a baseline middlebox (Split-TLS) and endpoints

The configuration of nginx as a Split-TLS middlebox is shown below.
If you want to test without the script we prepared, make h2load or ab on the client machines send requests to the responsible port.
Note that svr0 and svr1 refer to box3.kaist.ac.kr and box4.kaist.ac.kr, respectively.

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
You don't need to modify the configuration files. That's just for reference.


# Figure 8 - mmTLS

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/0ca8fc65-0562-465e-ac7c-f5c19882dc58" />

You run the mmTLS middlebox on box1.kaist.ac.kr.
Log in to box1.kaist.ac.kr first.

```Bash
ssh box1.kaist.ac.kr
```

We have prepared a pre-built mmTLS application which decrypts (and runs DPI with the ‘-p’ option which means pattern matching on) the payload for the given size.
The binary is in the mmTLS/proxies/mOS/mmTLS directory, so go to that directory and run the sample application.

```Bash
cd mmTLS/proxies/mOS/mmTLS
sudo ./my_ips -c 16
```

my_ips is a script that runs the mmTLS application.

'-c 16' means it should use 16 CPU cores.

'-l [monitoring size]' means it should decrypt first [monitoring_size]KB of the HTTP response. (Default is 64, which decrypts first 64KB.)

'-p' means run pattern matching using a snort3-10k-ruleset. We will use it on AE for figure 16.

When it starts, it periodically prints out the throughput after initialization.

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/92782579/679cdfd6-0570-4ea0-9782-f4bb582bdcaa" />

Then, on another ssh session to the middlebox machine (box1.kaist.ac.kr), ssh into the Bluefield-2 SmartNIC.

```Bash
ssh box1.kaist.ac.kr
```
```Bash
ssh 192.168.100.2 # on box1.kaist.ac.kr
```

Run the ‘key-server’ binary in the bf2_key_server directory.

```Bash
cd bf2_key_server
sudo ./key-server -c 8 -i p1
```

'-c 8' means it should use 8 CPU cores. (BF-2 has 8 cores.)

'-i p1' means it uses 'p1' interface to send raw packets to the host.

The ‘key-server’ will print out the trace on the secondary key channel as below.

<img style="width:400px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/6164bba2-b499-4298-bbeb-2cb9d213ceee" />

Then, open one more new ssh session and go to the same directory.
Then, execute ./run-mmtls-clients-persistent-gcm.sh to run all four client machines at the same time.


```Bash
cd mmTLS/proxies/mOS/mmTLS
./run-mmtls-clients-persistent-gcm.sh 64k
```

64k means the clients request 64KB objects from the server.
You can use 1k, 4k, 16k, 64k, 256k, 1m, 4m as well.
The output should look like below.

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/92782579/c0919b1f-5056-4af6-9bc5-3489e3069513" />

With the trace, you can check the persistent throughput of mmTLS with ECDHE-RSA-AES-256-GCM-SHA384 on TLS 1.3.
After checking the throughput, you should stop the clients, as below.

```Bash
./stop-clients.sh
```

Then, stop the 'my_ips' binary by entering Ctrl+C.

You can also test with DHE-RSA-AES-256-GCM-SHA256 with another script, run-mmtls-clients-persistent-cbc.sh.
Follow the same step above, but replace the script ‘run-mmtls-clients-persistent-gcm.sh’ with ‘run-mmtls-clients-persistent-cbc.sh’ as below.

```Bash
./run-mmtls-clients-persistent-cbc.sh 64k
```

Then, you will see the throughput with DHE-RSA-AES-256-GCM-SHA25 from the trace by my_ips.
When you are done, stop the clients and my_ips as instructed above.


# Figure 8 - split-TLS (nginx TLS proxy)
If you want to measure the throughput of split-TLS which is one of our baselines, stop my_ips and use nload on the middlebox instead.

```Bash
nload
```

You can see other interfaces using arrow keys (e.g., <-, ->).
nload prints the throughput of each interface in Gibps, so you should multiply (1.024 * 1.024 * 1.024) to convert it into Gbps.
[(We have confirmed that the source code of nload is actually computing Gibps rather than Gbps.)](https://github.com/rolandriegel/nload/blob/8f92dc04fad283abdd2a4538cd4c2093d957d9da/src/statistics.cpp#L125)
Or, you can check the bps by adding -u b option to nload.

```Bash
nload -u b
```

It will show the throughput in 'bps'.
Since nginx TLS proxy runs as background by default, you do not need to execute any middlebox application here.

Now ssh into box1.kaist.ac.kr, and run the client script.

```Bash
cd mmTLS/proxies/mOS/mmTLS
./run-splittls-clients-persistent-gcm.sh 64k
```

Now, you can check the throughput in the logs of nload (first session).
After checking the throughput, stop the clients, as below.

```Bash
./stop-clients.sh
```

You can also check DHE-RSA-AES-256-GCM-SHA256 with another script, run-splittls-clients-persistent-cbc.sh.

```Bash
./run-splittls-clients-persistent-cbc.sh 64k
```

Then, you will see the throughput withDHE-RSA-AES-256-GCM-SHA256 in the logs of nload.


# Figure 8 - mcTLS

We run mcTLS clients and an mcTLS server by ssh command to the clients and a server machine (wood1.kaist.ac.kr, core2.kaist.ac.kr, and box3.kaist.ac.kr, respectively) from the middlebox machine (box1.kaist.ac.kr).
So you do not need to log into clients or servers to execute the mcTLS endpoints.
Log into the middlebox machine.

```Bash
ssh box1.kaist.ac.kr
```

Go to the directory including my_ips, and just run the script, run-mctls-test.sh.

```Bash
cd ~/mmTLS/proxies/mOS/mmTLS
./run-mctls-test.sh 64k # size of objects requested by clients
```

You can use the size of requested objects among 1k, 4k, 16k, 64k, 256k, 1m, and 4m.

To see the throughput using nload, open a new ssh session to the middlebox machine (box1.kaist.ac.kr).

```Bash
ssh box1.kaist.ac.kr
```

```Bash
nload ens7f0np0 # on box1.kaist.ac.kr
```

Again, nload will show the throughput in Gibps, so don’t forget to multiply (1.024 * 1.024 * 1.024) with the printed throughput.


# Figure 9 - mmTLS

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/8a8e8669-d295-4a11-ab8c-f2d6bc1a74dd" />

It is similar to the evaluation of figure 8 as you run the middlebox on box1.kaist.ac.kr.
First, log into box1.kaist.ac.kr.

```Bash
ssh box1.kaist.ac.kr
```

Then, go to the directory including my_ips and run the sample application with a single CPU core.
We use only a single CPU core as 4 clients and 2 servers are not enough to saturate the middlebox with ephemeral connections since they incur huge overhead at endpoints.

```Bash
cd mmTLS/proxies/mOS/mmTLS
sudo ./my_ips -c 1
```

Then, ssh into the SmartNIC to run the 'key-server'.

```Bash
ssh 192.168.100.2
```

``` Bash
cd bf2_key_server # on 192.168.100.2
sudo ./key-server -c 8 -i p1
```

Now, run ephemeral clients instead of persistent ones.

```Bash
./run-mmtls-clients-ephemeral-gcm.sh # on box1.kaist.ac.kr
```

Since we fix the size of requested objects as 1KB for ephemeral connections, the script does not need any other parameters.

One thing different is that you should check the logs printed by ‘key-server’ running on SmartNIC.
It will print the total keys, keys per second, total connections, connections per second.
(In the context of key-server, a connection means the secondary key channel, which is persistent.)
The second log, keys per second shows the E2E connections established in one second.


# Figure 9 - split-TLS (nginx TLS proxy)

```Bash
ssh box1.kaist.ac.kr
```

Then, go to the directory including test scripts, and check the throughput using nload.

```Bash
cd mmTLS/proxies/mOS/mmTLS
./run-splittls-clients-ephemeral-gcm.sh
nload
```

You can check with another cipher suite, DHE-RSA-AES-256-GCM-SHA256 by the script below.

```Bash
./stop-clients.sh
./run-splittls-clients-ephemeral-cbc.sh
nload
```

After checking the throughput using nload, stop the clients.

```Bash
./stop-clients.sh
```

To test single core nginx TLS proxy, open a new ssh session to the middlebox machine (box1.kaist.ac.kr).

```Bash
ssh box1.kaist.ac.kr
```

Restart the nginx proxy with single configuration and see the throughput using nload.

```Bash
cd nginx-1.24.0
sudo killall nginx
sudo killall nginx* # to stop our custom nginx binaries if they are running
sudo ./nginx-dpi-0k -c /etc/nginx/1core.conf
```

On the first ssh session, run scripts.

```Bash
./stop-clients.sh
./run-splittls-clients-ephemeral-gcm.sh
nload
```

For DHE-RSA-AES-256-GCM-SHA256, run below.

```Bash
./stop-clients.sh
./run-splittls-clients-ephemeral-cbc.sh
nload
```



# Figure 10



# Figure 11 & Figure 12

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/8490913b-e9f3-4a3d-a99d-b5b59136eb1b" />


<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/867552f4-17bb-4ae3-95fd-f0ce04cefcc1" />


<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/0a857799-c9bb-4baf-a151-13c7304f39a9" />


We measure the average of 100 LAN response times and 100 WAN response times.
To simplify your evaluation, we have prepared a simple all-in-one script on the client side.
Log into wood1.kaist.ac.kr first.

```
ssh wood1.kaist.ac.kr
```

Since our script includes running the mmTLS or mcTLS (baseline) middlebox on box1.kaist.ac.kr as background program, you don't need to directly control the middlebox.
Move to the fig11 directory and run 'all-in-one.sh' script. It takes about 5 minutes.

```
cd ~/fig11
./kill-others.sh # When something goes wrong, run kill-others.sh and restart.
./all-in-one.sh
```

The result will be equivalent to figure 11 for both 11(a) -GCM- and 11(b) -CBC-.

For figure 12, we have prepared a simple 'all-in-one.sh' script on the client side as well as fig 11.

```
cd ~/fig12
./kill-others.sh
./all-in-one.sh
```

It will take about 10 minutes.
Note that this script modifies the default routing table entry to make the WAN traffic come and go via LAN (private network) interface instead of the default WAN (public network) interface.
(Unless, WAN traffic will not go to the middlebox which is connected via the LAN interface.)
If you are accessing via ssh to the WAN interface of the client (wood1), your ssh session will be lost.
Please do ssh from the access machine (box3), and run the script.
Since the news site is updated every hour, the result will be different with our evaluation.
We recommend you to check the gap between mmTLS and split-TLS, rather than the absolute response time of mmTLS.
Also, www.washingtonpost.com no longer supports http/1.1.
It currently accepts only http/2.
However, the nginx proxy (split-TLS) currently supports up to http/1.1 as a backend upstream connection, so we could not fully reproduce the result of split-TLS.
So, the result for split-TLS to washingtonpost will appear empty.
If you think the absolute response time is necessary, please let us know.
We will prepare other popular web sites to test split-TLS to WAN.


# Figure 13a - mmTLS

<img style="width:400px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/266cfaff-859c-48c0-a1ba-0a3b5b4da25b" />

It is the same as figure 8.
Log into the middlebox machine, and just run ‘my_ips’ with -c 1, 2, 4, 8, or 16.

```Bash
ssh box1.kaist.ac.kr
```

```Bash
cd mmTLS/proxies/mOS/mmTLS
sudo ./my_ips -c 1 # single core
```

Run the clients to request 64KB objects.

```Bash
./run-mmtls-clients-persistent-gcm.sh 64k
```

Then, check the throughput log printed by my_ips.
Unlike evaluation for figure 8, you should change the number of cores used in my_ips, with fixed size of objects requested by the clients.


# Figure 13a - split-TLS

You can restart the nginx daemon with a smaller number of cores as below.

```Bash
ssh box1.kaist.ac.kr
```

```Bash
# on box1.kaist.ac.kr
cd nginx-1.24.0
sudo killall nginx*
sudo ./nginx-dpi-0k -c /etc/nginx/1core.conf
```

The nginx configuration file, '1core.conf' configures nginx to use a single CPU core.
You can also try with '2core.conf', '4core.conf', '8core.conf', and '16core.conf' to change the number of cores employed by nginx.

Then, open a new session and execute the clients using the script, 'run-splittls-clients-persistent-gcm.sh' which is used above.

```Bash
ssh box1.kaist.ac.kr
```

```Bash
# on box1.kaist.ac.kr
cd mmTLS/proxies/mOS/mmTLS
./run-splittls-clients-persistent-gcm.sh 64k
```

Use nload to see the throughput on the middlebox machine.

```Bash
nload
```


# Figure 13b - E2E-TLS

<img style="width:400px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/7e0d5757-3172-4358-8d76-4c3228e25a48" />

Since the throughput of mmTLS middlebox is already measured by evaluation for figure 8, it is enough to measure the throughput of an endpoint TLS server.
Stop all the middlebox programs on the middlebox machine (box1.kaist.ac.kr), and run the clients.

```Bash
ssh box1.kaist.ac.kr
```

```Bash
# on box1.kaist.ac.kr
cd mmTLS/proxies/mOS/mmTLS
./stop-clients.sh
./run-e2e-clients-persistent-gcm.sh [file size]
```

Check the printed throughput by nload.

```Bash
ssh box1.kaist.ac.kr
```
```Bash
nload
```

After checking the throughput once, you should stop the clients by executing 'stop-clients.sh'.

```Bash
./stop-clients.sh # on the same ssh session that execute the script above
```

You might want to run the test for file size 1k, 4k, 16k, 64k, 256k, 1m, and 4m.
Just replace the file size with one that you want to test with.



# Figure 14

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/8b8620b1-af71-4ea4-aa2c-2b77fc8d571a" />

Go to the openssl-modified directory on the mmTLS root directory, and run the 'tag' script.
It generates private tags in various methods for record size of 1KB, 2KB, 4KB, 8KB, and 16KB, then measures the relative overhead using average time spent.

```Bash
ssh box1.kaist.ac.kr
```

```Bash
# on box1.kaist.ac.kr
cd mmTLS/openssl-modified/tag-gen
./tag
```

It will take about 1 minute.
Each column means Original (no private tag), mmTLS (optimal), Reusing ciphertext, and Double tags (naive), respectively.



# Figure 15 - Default Chromium (for split-TLS and E2E-TLS

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/b6a6ccdd-f3d8-4de2-9f8d-5670dbf6cfab" />

This evaluation needs chromium GUI application and the extension program.
We manually measured the page load time shown by the chromium extension, so it is difficult to automatically reproduce the figure.
Here, we only provide how to run the test manually.

First log in to the client machine, box2.kaist.ac.kr with -X option to enable X window.
You should have been connected to the first access server (box3.kaist.ac.kr) with -X option before ssh into the client machine.

```Bash
# on your local
ssh -X [guest ID]@box3.kaist.ac.kr
```

Then, log in to the machine that has pre-built chromium with -X option.

```Bash
# on box3.kaist.ac.kr
ssh -X box2.kaist.ac.kr
```

Before testing, unset mmTLS configuration and go to the chromium directory.

```Bash
# on box2.kaist.ac.kr
sudo ./unmmtls.sh
cd chromium/src/out
```

You can run the default chrome with some options as below.

```Bash
./Default/chrome --ignore-certificate-errors --disable-proxy-certificate-handler --test-type
```

If you want to test split-TLS, type https://10.11.95.1:21443 on the URL space.
Else if you want to test E2E-TLS, type https://10.11.95.3:1443 on the URL space as below.

<img style="width:1000px;" src="https://github.com/TNET-SNU/mmTLS/assets/92782579/64a7ca03-6777-4869-aff9-141e831bfb28" />

It will load the page with a number of embedding resources.
After loading, click the first extension and check the total loading timing. (132ms in the screenshot)
You can repeat by typing **"Ctrl + F5". (No refresh button or "only F5", since they do not establish a new TLS connection.)**
Since it's a LAN connection, the result will be pretty stable, even though you do not repeat it 100 times fully to measure the average.

However, the absolute result will not be exactly same as the figure, since the chromium client machine is changed.
Again, we recommend you to check the gap between E2E-TLS/mmTLS and split-TLS in terms of the page load time.

If you want to change the number of embedding resources, modify the main page on the server side as below.

```Bash
# on box3.kaist.ac.kr
ssh box4.kaist.ac.kr
```

```
# on box4.kaist.ac.kr
cd /usr/share/nginx/html
sudo ./genhtml.sh 100 # number of embedding resources
```
It will change the same index page to include more resources.
(Since chromium is based on GUI, clicking and re-typing other resources on chromium is a more cumbersome task than directly modifying the same index page on the server.)



# Figure 15 - mmTLS-ported Chromium

To test the mmTLS-ported chromium, ssh into the client machine with '-X' option.

```Bash
# on your local
ssh -X box3.kaist.ac.kr
```

```Bash
# on box3.kaist.ac.kr
ssh -X box2.kaist.ac.kr
```

Run the 'mmtls.sh' script to setup configuration for mmTLS and go to the chromium directory.

```Bash
# on box2.kaist.ac.kr
sudo ./mmtls.sh
cd chromium/src/out
```

Then, run the mmTLS middlebox and the key-server on the middlebox machine (box1.kaist.ac.kr) in advance.
We provide a script that runs both automatically.

```Bash
./run-mmtls-middlebox.sh
```

Now, you can run mmTLS-ported chromium.

```Bash
./mmtls/chrome --ignore-certificate-errors --disable-proxy-certificate-handler --test-type
```

To test mmTLS, type https://10.11.95.3:1443 on the URL apace.
The other steps are the same with the section above.

After testing, you should stop the mmtls middlebox.

```Bash
./stop-mmtls-middlebox.sh
```



# Figure 16 - mmTLS

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/e83eee3c-58f2-4450-b8f9-446800c29a14" />

First, log in to the middlebox machine (box1.kaist.ac.kr).
```Bash
ssh box1.kaist.ac.kr
```

Run my_ips app with option -p and -l on the middlebox machine.

```Bash
cd mmTLS/proxies/mOS/mmTLS
sudo ./my_ips -c 16 -p -l 16 # DPI on first 16KB
```

Then, start the clients using run-h2load-persistent.sh.

```Bash
./run-h2load-persistent.sh 1m
```

my_ips app will print the real-time throughput.



# Figure 16 - split-TLS (nginx TLS proxy)

To run split-TLS DPI, use the pre-built binaries, nginx-dpi-16k, nginx-dpi-32k, nginx-dpi-64k, and nginx-dpi-128k on nginx-1.24.0 directory at the middlebox machine (box1.kaist.ac.kr).

```Bash
ssh box1.kaist.ac.kr
```

```Bash
cd nginx-1.24.0
sudo ./nginx-dpi-16k -c /etc/nginx/16.conf # replace the binary as you want
```

Then, measure the throughput using nload on the middlebox machine (box1.kaist.ac.kr).


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
