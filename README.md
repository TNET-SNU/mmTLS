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
We have set up a simple testbed to evaluate the functionality of our work, used for ATC’24 artifact evaluation.
Please let us know (cerotyki@gmail.com or HotCRP) and we will provide the credential to login to the test machine.
Our testbed consists of 7 machines: 4 clients, 1 middlebox, and 2 backend servers (see the picture below) and all of them are accessible by ssh.
Please log into the access server (i.e., box3.kaist.ac.kr) first, and you can log into other machines from it.
The figure below depicts the topology of our testbed.

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/7b82e7f2-834f-474c-9cad-c8b43e8ee3f1" />

This page assumes that you have access to box3.kaist.ac.kr via ssh.
The first login to the access machine should be done as "atc-ae", which is an account we provide for your first access.
The second login to the other machines from the access machine should be done as "junghan", which has all the binaries and scripts.

```Bash
# on your local machine
ssh atc-ae@box3.kaist.ac.kr -p [port]
```

Now you can log into the middlebox machine (box1.kaist.ac.kr) which has the AE scripts for figure 8, 9, 10, 13, 14, and 16.

```Bash
# on box3.kaist.ac.kr
ssh junghan@box1.kaist.ac.kr
```

Or, you can log into the client machine (wood1.kaist.ac.kr) which has the AE scripts for figure 11, 12, and 17.

```Bash
# on box3.kaist.ac.kr
ssh junghan@wood1.kaist.ac.kr
```

For figure 15, which requires compiled chromium, you should log into box2.kaist.ac.kr with -X option to use X window.

```Bash
# on your local machine
ssh -X atc-ae@box3.kaist.ac.kr -p [port]
```

```Bash
# on box3.kaist.ac.kr
ssh -X junghan@box2.kaist.ac.kr
```



# Figure 8 - Persistent Connection Test (25 minutes)

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/0ca8fc65-0562-465e-ac7c-f5c19882dc58" />

We have prepared an automated script to generate results for figure 8.
Log in to box1.kaist.ac.kr first.

```Bash
# on atc-ae@box3.kaist.ac.kr
ssh junghan@box1.kaist.ac.kr
```

Then, run the script, 'run-persistent.sh'

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-persistent.sh
```

It will take about **25 minutes.**
The script will print the throughput of mmTLS (1), mmTLS (2), splitTLS (1), splitTLS (2), and mcTLS (2) as below.

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/1b3a9327-c972-438a-9243-bd70f2885b26" />



# Figure 9 - Ephemeral Connection Test (5 minutes)

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/8a8e8669-d295-4a11-ab8c-f2d6bc1a74dd" />


```diff
- For AE of Figure 9, we have found a mis-configuration in our last evaluation.
- With a correct configuration, mmTLS produces 40K/s, 20% lower than figure 9.
- We also note that mcTLS achieves a higher performance.
- Despite the change, we still observe that mmTLS achieves 40x to 60x performance improvement.

- We will update the final result for the camera-ready version.
- Sorry for the confusion, but we will fix this graph for the camera-ready version.
```

Login to the middlebox machine (box1.kaist.ac.kr).

```Bash
# on atc-ae@box3.kaist.ac.kr
ssh junghan@box1.kaist.ac.kr
```

Then, run the script, 'run-ephemeral.sh' as below.

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-ephemeral.sh
```
This script will take about **5 minutes** and print the throughput as below.

<img style="width:600px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/ed67ad11-4847-430d-a050-ef2947eb31c5" />



# Figure 11 - Response Time - LAN (6 minutes)

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/8490913b-e9f3-4a3d-a99d-b5b59136eb1b" />

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/867552f4-17bb-4ae3-95fd-f0ce04cefcc1" />

We measure the average of 100 LAN response times and 100 WAN response times.
To simplify your evaluation, we have prepared a simple all-in-one script on the client side.
Log into wood1.kaist.ac.kr first.

```Bash
# on atc-ae@box3.kaist.ac.kr
ssh junghan@wood1.kaist.ac.kr
```

Move to the fig11 directory and run 'all-in-one.sh' script. It takes about **6 minutes.**

```Bash
# on wood1.kaist.ac.kr
cd ~/fig11
./all-in-one.sh
```

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/44983fe6-d176-435b-b540-621020a0c2ce" />

The result will be equivalent to figure 11 for both 11(a) -GCM- and 11(b) -CBC-.

```diff
- For AE of Figure 11 (a), we found that there were disk IO delays in E2E response time.
- On this evaluation, we removed the disk IO by warming up the web servers.
- For AE of Figure 11 (b), we found that the key exchange protocols were not consistent among mmTLS and the baselines.
- mmTLS and Split-TLS were using RSA for key exchange while mcTLS was using DHE with 1024-bit DH parameter.
- We make them use a common key exchange protocol, DHE with 2048-bit DH parameter, which is supported by mcTLS.

- Sorry for the confusion, but we will fix this graph for the camera-ready version.
```

# Figure 12 - Response Time - WAN (15 minutes)

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/0a857799-c9bb-4baf-a151-13c7304f39a9" />

For figure 12, we have prepared a simple 'all-in-one.sh' script on the client side as well as fig 11.
Log into wood1.kaist.ac.kr first.

```Bash
# on atc-ae@box3.kaist.ac.kr
ssh junghan@wood1.kaist.ac.kr
```

Then, run below.

```
# on wood1.kaist.ac.kr
cd ~/fig12
./all-in-one.sh
```

It will take about **15 minutes,** and print the result as below.

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/d763d77f-a50c-4094-b8e4-acb174dbd4aa" />

Note that this script modifies the default routing table entry to make the WAN traffic come and go via LAN (private network) interface instead of the default WAN (public network) interface.
(Unless, WAN traffic will not go to the middlebox which is connected via the LAN interface.)
If you are accessing via ssh to the WAN interface of the client (wood1), your ssh session will be lost.
Please do ssh from the access machine (box3), and run the script.
Since the news site is updated every hour, the result will be different with our evaluation.
We recommend you to check the gap between mmTLS and split-TLS, rather than the absolute response time of mmTLS.
Also, www.washingtonpost.com no longer supports http/1.1.
It currently accepts only http/2.
However, the nginx proxy (split-TLS) currently supports up to http/1.1 as a backend upstream connection, so we could not fully reproduce the result of split-TLS.
So, the result for washingtonpost will appear empty.
If you think the absolute response time is necessary, please let us know.
We will prepare other popular web sites to test split-TLS to WAN.



# Figure 13a - Scalability (7 minutes)

<img style="width:400px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/266cfaff-859c-48c0-a1ba-0a3b5b4da25b" />

Log into the middlebox machine, and just run the script, 'run-scalability.sh', which automatically tests mmTLS middlebox and nginx TLS proxy with various numbers of cores.

```Bash
# on atc-ae@box3.kaist.ac.kr
ssh junghan@box1.kaist.ac.kr
```

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-scalability.sh
```

The script will take about **7 minutes** and print the result as below.

<img style="width:600px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/f5b5c638-9001-4a17-adf8-9d9afb211a42" />



# Figure 13b - Comparison with E2E TLS Server (7 minutes)

<img style="width:400px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/7e0d5757-3172-4358-8d76-4c3228e25a48" />

Login to the middlebox machine (box1.kaist.ac.kr).

```Bash
# on atc-ae@box3.kaist.ac.kr
ssh junghan@box1.kaist.ac.kr
```

Run the script below.

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-compare-with-e2e.sh
```

It will take about **7 minutes** and finally print the throughput of mmTLS and E2E-TLS as below.

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/aeaedb59-1974-4109-9d64-ed8ea14a1d20" />



# Figure 14 - Overhead on Tag Generation (2 minutes)

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/8b8620b1-af71-4ea4-aa2c-2b77fc8d571a" />

Go to the openssl-modified directory on the mmTLS root directory, and run the 'run-tag.sh' script.
It generates private tags in various methods for record size of 1KB, 2KB, 4KB, 8KB, and 16KB, then measures the relative overhead using average time spent.

```Bash
# on atc-ae@box3.kaist.ac.kr
ssh junghan@box1.kaist.ac.kr
```

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-tag.sh
```

It will take about **2 minutes.**
Each column means Original (no private tag), mmTLS (optimal), Reusing ciphertext, and Double tags (naive), respectively.

<img style="width:600px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/026543e1-c9f4-43dd-b173-a8318528322b" />


# Figure 15 - Web Browser Test

## Note

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/b6a6ccdd-f3d8-4de2-9f8d-5670dbf6cfab" />

This evaluation needs chromium GUI application and the extension program, since we manually measure the page load time shown by the extension program.
For the same reason, it is difficult to automatically reproduce the figure, so we only provide the manual test in this section.

To execute GUI chromium, X window server should be installed on your local machine.
Please make sure your terminal can open a GUI application via X window.
There are many X window server for various platform.
If you are not familiar with X window, use MobaXterm, which is a terminal with an embedded X window server.

Here, we note that the absolute result may not be exactly same as the figure above, since the chromium client machine is changed from the last evaluation.
Again, we recommend you to check the gap between E2E-TLS/mmTLS and split-TLS in terms of the page load time.

## Reproducing

First log in to the client machine, box2.kaist.ac.kr with -X option to enable X window.
You should have been connected to the first access server (box3.kaist.ac.kr) with -X option before ssh into the client machine.

```Bash
# on your local machine
ssh -X atc-ae@box3.kaist.ac.kr
```

Then, log in to the machine that has the pre-built chromium with -X option.

```Bash
# on atc-aebox3.kaist.ac.kr
ssh -X junghan@box2.kaist.ac.kr
```

You can run the split-TLS chromium using the script below.

```Bash
# on box2.kaist.ac.kr
./split-chromium.sh 200 # choose among 10, 20, 50, 100, and 200
```

It will load the page consisting of 200 embedding resources as below.

<img style="width:1000px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/92fab4de-036c-41d9-8104-9eeeebce6e5b" />

After loading, click the first extension and check the total loading timing. (952ms in the screenshot)
You can repeat by typing **"Ctrl + F5". (No refresh button or "only F5", since they do not establish a new TLS connection.)**
Since it's a LAN connection, the result will be pretty stable, even though you do not repeat it 100 times fully to measure the average.

If you want to change the number of embedding resources, run the script with an argument among 10, 20, 50, 100, and 200.

After checking the page load time with Split-TLS chromium, close the browser using **"Alt + F4"** and open E2E-TLS chromium using the script below.

```Bash
# on box2.kaist.ac.kr
./e2e-chromium.sh 200 # choose among 10, 20, 50, 100, and 200
```

You can repeat the page loading by typing "Ctrl + F5", and change the number of embedding resources as well.

After checking the page load time with E2E-TLS chromium, close the browser and open mmTLS chromium using the script below.

```Bash
# on box2.kaist.ac.kr
./mm-chromium.sh 200 # choose among 10, 20, 50, 100, and 200
```

This script will setup the mmTLS configuration and remotely runs the mmTLS middlebox.
Again, you can repeat the test and change the number of embedding resources.



# Figure 16 - DPI Application on the TLS Middlebox (6 minutes)

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/e83eee3c-58f2-4450-b8f9-446800c29a14" />

First, login to the middlebox machine (box1.kaist.ac.kr).

```Bash
# on atc-ae@box3.kaist.ac.kr
ssh junghan@box1.kaist.ac.kr
```

Then, run the script below.

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-dpi.sh
```

It will take about **6 minutes**, and print the result as below.

<img style="width:600px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/8a23a6ab-9701-4e3c-9f10-3f1a79cbc94c" />



# Figure 17 - Another Sample Application - Cipherstats (30 minutes)

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/fe423586-39d1-4f64-8ed3-86d01965fe7f" />

We provide an all-in-one script that runs the mmTLS middlebox application, 'my_cipherstat' on the middlebox machine (box1.kaist.ac.kr) and 'key-server' on the SmartNIC.
Login to the client machine (wood1.kaist.ac.kr).

```Bash
# on atc-ae@box3.kaist.ac.kr
ssh junghan@wood1.kaist.ac.kr
```

Then, go to the fig17 directory, and run 'all-in-one.sh' as below.

```Bash
# on box1.kaist.ac.kr
cd ~/fig17
./all-in-one.sh alexa-test
```

It will print whether the site is accessible from our testbed as below.

<img style="width:400px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/9c16ceb8-cb40-4361-80ab-718dbac721d0" />

It will take about **30 minutes.**
At the end of the script, it will stop the middlebox and print the summarized result by bringing it from the middlebox machine (box1.kaist.ac.kr).

Since the web sites on WAN are updated every hour, the result might not be exactly the same as the figure.



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
You don't need to modify the configuration files. It's just for reference.
