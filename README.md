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
# on your local
ssh [guest-ID]@box3.kaist.ac.kr -p [port]
```

Now you can log into the middlebox machine (box1.kaist.ac.kr) which has the AE scripts for figure 8, 9, 10, 13, 14, and 16.

```Bash
# on box3.kaist.ac.kr
ssh box1.kaist.ac.kr
```

Or, you can log into the client machine (wood1.kaist.ac.kr) which has the AE scripts for figure 11, 12, and 17.

```Bash
# on box3.kaist.ac.kr
ssh wood1.kaist.ac.kr
```

For figure 15, which requires compiled chromium, you should log into box2.kaist.ac.kr with -X option to use X window.

```Bash
# on your local
ssh -X [guest-ID]@box3.kaist.ac.kr -p [port]
```

```Bash
# on box3.kaist.ac.kr
ssh -X junghan@box2.kaist.ac.kr
```



# Figure 8

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/0ca8fc65-0562-465e-ac7c-f5c19882dc58" />

We have prepared a automated script to generate results for figure 8.
Log in to box1.kaist.ac.kr first.

```Bash
# on box3.kaist.ac.kr
ssh box1.kaist.ac.kr
```

Then, run the script, 'run-persistent.sh'

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-persistent.sh
```

It will take about 25 minutes.
The script will print the throughput of mmTLS (1), mmTLS (2), splitTLS (1), splitTLS (2), and mcTLS (2) as below.






# Figure 9

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/8a8e8669-d295-4a11-ab8c-f2d6bc1a74dd" />


```diff
- For AE of Figure 9, we found that there was a mis-configuration at the last evaluation done before submitting our paper for AE.
- The result that you reproduce in this section will be smaller than the figure, but it is correct result.
- They will be about 40K/s, 0.63K/s, and 9K/s for 1 core mmTLS, 1 core nginx, and 16 core nginx, respectively.
- We will update the final result for the camera-ready version.
- Sorry for your inconvenience.
```


## mmTLS
It is similar to the evaluation of figure 8 as you run the middlebox on box1.kaist.ac.kr.
First, log into box1.kaist.ac.kr.

```Bash
# on box3.kaist.ac.kr
ssh box1.kaist.ac.kr
```

Then, go to the directory including 'my_ips' and run the sample application with a single CPU core as background and run the 'key-server' on the SmartNIC.
(We use only a single CPU core for the mmTLS middlebox as 4 clients and 2 servers are not enough to saturate the middlebox with ephemeral connections since they incur huge overhead at endpoints.)
For your convenience, we provide the script below which runs the single core 'my_ips' on the host and the 'key-server' on the SmartNIC.

```Bash
# on box1.kaist.ac.kr
cd mmTLS/proxies/mOS/mmTLS
./run-splittls-keyserver-ephemeral.sh
```

The script will print out the trace on the secondary key channel as below.

<img style="width:400px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/6164bba2-b499-4298-bbeb-2cb9d213ceee" />

The E2E connection establishments in one second is denoted as key/s in the printed logs.

Now, open a new session to the middlebox machine (box1.kaist.ac.kr) and run ephemeral clients.0

```Bash
# on box3.kaist.ac.kr
ssh box1.kaist.ac.kr
```

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-mmtls-clients-ephemeral-gcm.sh
```

It will print the total keys, keys per second, total connections, connections per second.
(In the context of key-server, a connection means the secondary key channel, which is persistent.)
**The second log, keys per second shows the E2E connections established in one second.**

After checking the throughput, stop the clients, 'my_ips', and 'key-server'.

```Bash
# on box1.kaist.ac.kr
./stop-clients.sh
```



## split-TLS (nginx TLS proxy)

We use the 'key-server' on the SmartNIC to measure the E2E connections per second.

```Bash
# on box3.kaist.ac.kr
ssh box1.kaist.ac.kr
```

Again, for your convenience, we provide a script on the middlebox host to run remotely execute the 'key-server' on the SmartNIC.

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-splittls-middlebox.sh
./run-splittls-keyserver-ephemeral.sh
```

It will print the E2E connection establishments in one second which is denoted as key/s in the printed logs.

Now, it is ready for testing.
To start the clients, open a new session to the middlebox machine (box1.kaist.ac.kr).

```Bash
# on box3.kaist.ac.kr
ssh box1.kaist.ac.kr
```

Then, run the test scripts, and check the logs by 'key-server' running on the first ssh session.

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-splittls-clients-ephemeral-gcm.sh
```

After checking the throughput, stop the clients.

```Bash
# on box1.kaist.ac.kr
./stop-clients.sh
```

You can check with another cipher suite, DHE-RSA-AES-256-GCM-SHA256 by the script below.

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-splittls-clients-ephemeral-cbc.sh
```

After checking the key/s on the logs by 'key-server', stop the clients.

```Bash
# on box1.kaist.ac.kr
./stop-clients.sh
```

To test single core nginx TLS proxy, open a new ssh session to the middlebox machine (box1.kaist.ac.kr).

```Bash
# on box3.kaist.ac.kr
ssh box1.kaist.ac.kr
```

Restart the nginx proxy with single configuration and see the throughput using the 'key-server'.

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-splittls-middlebox.sh 1 # means 1 core employed by nginx
./run-splittls-keyserver-ephemeral.sh
```

Then, run the test scripts, and check the logs by 'key-server' running on the first ssh session.

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-splittls-clients-ephemeral-gcm.sh
```

After checking the key/s on the logs by 'key-server', stop the clients.

```Bash
./stop-clients.sh
```

For DHE-RSA-AES-256-GCM-SHA256, run below instead of 'run-splittls-clients-ephemeral-gcm.sh'.

```Bash
./run-splittls-clients-ephemeral-cbc.sh
```

After checking the throughput, stop the clients.

```Bash
./stop-clients.sh
```




# Figure 10



# Figure 11

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/8490913b-e9f3-4a3d-a99d-b5b59136eb1b" />

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/867552f4-17bb-4ae3-95fd-f0ce04cefcc1" />

We measure the average of 100 LAN response times and 100 WAN response times.
To simplify your evaluation, we have prepared a simple all-in-one script on the client side.
Log into wood1.kaist.ac.kr first.

```Bash
# on box3.kaist.ac.kr
ssh wood1.kaist.ac.kr
```

Since our script includes running the mmTLS or mcTLS (baseline) middlebox on box1.kaist.ac.kr as background program, you don't need to directly control the middlebox.
Move to the fig11 directory and run 'all-in-one.sh' script. It takes about 6 minutes.

```Bash
# on wood1.kaist.ac.kr
cd ~/fig11
./kill-others.sh # When something goes wrong, run kill-others.sh and restart.
./all-in-one.sh
```

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/8f266f7f-e2db-4367-85fe-19866089228c" />

The result will be equivalent to figure 11 for both 11(a) -GCM- and 11(b) -CBC-.



# Figure 12

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/0a857799-c9bb-4baf-a151-13c7304f39a9" />

For figure 12, we have prepared a simple 'all-in-one.sh' script on the client side as well as fig 11.
Log into wood1.kaist.ac.kr first.

```Bash
# on box3.kaist.ac.kr
ssh wood1.kaist.ac.kr
```

Then, run below.

```
# on wood1.kaist.ac.kr
cd ~/fig12
./kill-others.sh
./all-in-one.sh
```

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/d763d77f-a50c-4094-b8e4-acb174dbd4aa" />

It will take about 15 minutes.
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



# Figure 13a

<img style="width:400px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/266cfaff-859c-48c0-a1ba-0a3b5b4da25b" />

## mmTLS

It is the same as figure 8.
Log into the middlebox machine, and just run the script, 'run-mmtls-middlebox-persistent.sh' with an argument of 1, 2, 4, 8, or 16.

```Bash
# on box3.kaist.ac.kr
ssh box1.kaist.ac.kr
```

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
run-mmtls-middlebox-persistent.sh 1 # 1 means the number of cores employed by the 'my_ips'
```

To run the clients to request 64KB objects, open a new session and run the script as below.

```Bash
# on box3.kaist.ac.kr
ssh box1.kaist.ac.kr
```

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-mmtls-clients-persistent-gcm.sh 64k
```

Then, check the throughput log printed by 'run-mmtls-middlebox-persistent.sh' on the first session.
Unlike the evaluation for figure 8, you should change the number of cores employed by 'run-mmtls-middlebox-persistent.sh', while fixing the size of objects requested as 64k.

For example, to check the 2-core throughput, run as below.

```Bash
# on box3.kaist.ac.kr
ssh box1.kaist.ac.kr
```

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
run-mmtls-middlebox-persistent.sh 2 # 2 means the number of cores employed by the 'my_ips'
```

The following steps are the same as the single core test above.
Run the clients with the script.

```Bash
# on box3.kaist.ac.kr
ssh box1.kaist.ac.kr
```

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-mmtls-clients-persistent-gcm.sh 64k
```



## split-TLS (nginx TLS proxy)

You can restart the nginx daemon with a smaller number of cores as below.
Login to the middlebox machine (box1.kaist.ac.kr).

```Bash
# on box3.kaist.ac.kr
ssh box1.kaist.ac.kr
```

Then, run the nginx TLS proxy ans measure the throughput using nload.

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-splittls-middlebox.sh 16 # 16 means the number of cores employed by nginx
nload
```

You can also try with 1, 2, 4, and 8 to change the number of cores employed by nginx.

Then, open a new session and execute the clients using the script, 'run-splittls-clients-persistent-gcm.sh' which is used above.

```Bash
# on box3.kaist.ac.kr
ssh box1.kaist.ac.kr
```

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-splittls-clients-persistent-gcm.sh 64k
```

After checking, stop the clients.

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./stop-clients.sh
```



# Figure 13b

<img style="width:400px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/7e0d5757-3172-4358-8d76-4c3228e25a48" />

## E2E-TLS

Since the throughput of mmTLS middlebox is already measured by evaluation for figure 8, it is enough to measure the throughput of an endpoint TLS server.
Run the nginx as an endpoint TLS server and measure the throughput using nload.

```Bash
# on box3.kaist.ac.kr
ssh box1.kaist.ac.kr
```

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-splittls-middlebox.sh 16
nload
```

Then, run the clients.

```Bash
./stop-clients.sh
./run-e2e-clients-persistent-gcm.sh [file size]
```

After checking the throughput once, you should stop the clients by executing 'stop-clients.sh'.

```Bash
./stop-clients.sh
```

You might want to run the test for file size 1k, 4k, 16k, 64k, 256k, 1m, and 4m.
Just replace the [file size] with one that you want to test with.



# Figure 14

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/8b8620b1-af71-4ea4-aa2c-2b77fc8d571a" />

Go to the openssl-modified directory on the mmTLS root directory, and run the 'tag' script.
It generates private tags in various methods for record size of 1KB, 2KB, 4KB, 8KB, and 16KB, then measures the relative overhead using average time spent.

```Bash
# on box3.kaist.ac.kr
ssh box1.kaist.ac.kr
```

```Bash
# on box1.kaist.ac.kr
cd mmTLS/proxies/mOS/mmTLS
./tag
```

It will take about 1 minute.
Each column means Original (no private tag), mmTLS (optimal), Reusing ciphertext, and Double tags (naive), respectively.



# Figure 15

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/b6a6ccdd-f3d8-4de2-9f8d-5670dbf6cfab" />

## Default Chromium (for split-TLS and E2E-TLS)

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
sudo ~/unmmtls.sh
cd chromium/src/out
```

You can run the default chrome with some options as below.

```Bash
./Default/chrome --ignore-certificate-errors --disable-proxy-certificate-handler --test-type
```

If you want to test split-TLS, type https://10.11.95.1:21443/200.html on the URL space.
Else if you want to test E2E-TLS, type https://10.11.95.3:1443/200.html on the URL space as below.

<img style="width:1000px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/726cd67d-5768-4dfb-b56a-02f7e31a4e48" />

It will load the page with a number of embedding resources.
After loading, click the first extension and check the total loading timing. (754ms in the screenshot)
You can repeat by typing **"Ctrl + F5". (No refresh button or "only F5", since they do not establish a new TLS connection.)**
Since it's a LAN connection, the result will be pretty stable, even though you do not repeat it 100 times fully to measure the average.

However, the absolute result will not be exactly same as the figure, since the chromium client machine is changed.
Again, we recommend you to check the gap between E2E-TLS/mmTLS and split-TLS in terms of the page load time.

If you want to change the number of embedding resources, change the name of requested html file to one among 10.html, 20.html, 50.html, 100.html, and 200.html
The number in the name of html file means the number of 136KB embedding resources.



## mmTLS-ported Chromium

To test the mmTLS-ported chromium, ssh into the client machine with '-X' option.

```Bash
# on your local
ssh -X [guest-id]@box3.kaist.ac.kr -p [port]
```

```Bash
# on box3.kaist.ac.kr
ssh -X junghan@box2.kaist.ac.kr
```

Run the 'mmtls.sh' script to setup configuration for mmTLS and go to the chromium directory.

```Bash
# on box2.kaist.ac.kr
sudo ~/mmtls.sh
cd chromium/src/out
```

Then, run the mmTLS middlebox and the key-server on the middlebox machine (box1.kaist.ac.kr).
We provide a script that runs both automatically.

```Bash
# on the same directory on box2.kaist.ac.kr
./run-mmtls-middlebox.sh
```

Now, you can run mmTLS-ported chromium.

```Bash
./mmtls/chrome --ignore-certificate-errors --disable-proxy-certificate-handler --test-type
```

To test mmTLS, type https://10.11.95.3:1443/[number-of-embedding-resources].html on the URL apace.
The other steps are the same with the section above.

After testing, you should stop the mmtls middlebox.

```Bash
./stop-mmtls-middlebox.sh
```



# Figure 16

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/e83eee3c-58f2-4450-b8f9-446800c29a14" />

## DPI on mmTLS

First, login to the middlebox machine (box1.kaist.ac.kr).

```Bash
# on box3.kaist.ac.kr
ssh box1.kaist.ac.kr
```

Run the script 'run-mmtls-middlebox-dpi.sh' which executes 'my_ips' app with option -p and -l on the middlebox machine.

'-p' option means 'my_ips' should do DPI on the decrypted content.

'-l [monitoring size]' option means it should decrypt first [monitoring_size]KB of the HTTP response. (Default is 64, which decrypts first 64KB.)

```Bash
# on box1.kaist.ac.kr
cd mmTLS/proxies/mOS/mmTLS
./run-mmtls-middlebox-dpi.sh 16 # DPI on first 16KB
```

Then, open a new session and start the clients using the script, 'run-mmtls-clients-persistent-gcm.sh'.

```Bash
# on box1.kaist.ac.kr
./run-mmtls-clients-persistent-gcm.sh 1m
```

'run-mmtls-middlebox-dpi.sh' will print the real-time throughput.

After checking the throughput, stop the clients.

```Bash
./stop-clients.sh
```

You can try DPI with 32KB, 64KB, and 128KB by replacing the argument as below.

```Bash
# on box1.kaist.ac.kr
cd mmTLS/proxies/mOS/mmTLS
./run-mmtls-middlebox-dpi.sh 128 # DPI on first 128KB
```



## DPI on split-TLS (nginx TLS proxy)

To run split-TLS DPI, use the pre-built binaries, nginx-dpi-16k, nginx-dpi-32k, nginx-dpi-64k, and nginx-dpi-128k on nginx-1.24.0 directory at the middlebox machine (box1.kaist.ac.kr).

```Bash
# on box3.kaist.ac.kr
ssh box1.kaist.ac.kr
```

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-splittls-middlebox-dpi.sh 16 # 16 means DPI on the first 16KB of HTTP response
nload
```

nload will print the real-time throughput in Gibps.

Then, start the clients using the script, 'run-splittls-clients-persistent-gcm.sh'.

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-splittls-clients-persistent-gcm.sh 1m
```

After checking the throughput, stop nload by entering Ctrl+C, and stop the clients.

```Bash
# on box1.kaist.ac.kr
./stop-clients.sh
```

You can try DPI with 32KB, 64KB, and 128KB by replacing the argument as below.

```Bash
# on box1.kaist.ac.kr
cd ~/mmTLS/proxies/mOS/mmTLS
./run-splittls-middlebox-dpi.sh 128 # 128 means DPI on the first 128KB of HTTP response
nload
```



# Figure 17

<img style="width:800px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/fe423586-39d1-4f64-8ed3-86d01965fe7f" />

We provide an all-in-one script that runs the mmTLS middlebox application, 'my_cipherstat' on the middlebox machine (box1.kaist.ac.kr) and 'key-server' on the SmartNIC.
Login to the client machine (wood1.kaist.ac.kr).

```Bash
# on box3.kaist.ac.kr
ssh wood1.kaist.ac.kr
```

Then, go to the fig17 directory, and run 'all-in-one.sh' as below.

```Bash
# on box1.kaist.ac.kr
cd ~/fig17
./all-in-one.sh alexa-test
```

It will print whether the site is accessible from our testbed as below.

<img style="width:400px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/5b94af03-2bac-4680-89e0-5b2a279ec0bd" />

It will take about 30 minutes.
At the end of the script, it will stop the middlebox and print the summarized result by reading it from the middlebox machine (box1.kaist.ac.kr).

<img style="width:400px;" src="https://github.com/TNET-SNU/mmTLS/assets/53930924/56dfbad2-3593-4c4a-b5c1-2f1ed14f0531" />

The result which is equivalent to the figure 17.
Since the web sites on WAN are updated every hour, the result might not be exactly same as the figure.



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
