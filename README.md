# DMZ Design Using Linux Netfilter

## 1. Scenario

[![network-infrastructure-diagram](https://raw.githubusercontent.com/t-ho/dmz-netfilter/master/assets/diagram.png)](https://github.com/t-ho/dmz-netfilter)

The network infrastructure has the following details:

- Linux Gateway with three ethernet interfaces: eth0: `192.168.0.1` (attached to the internal LAN: `192.168.0.0/24`); eth1: `192.168.10.1` (attached to the DMZ segment: `192.168.10.0/24`) and eth2: `2.2.2.2` (attached to the ISP provider network with default GW: `2.2.2.1`).
- Mail server: `192.168.10.2`, listening on TCP/25.
- Web server: `192.168.10.3`, running Apache on ports 80 and 443.
- DNS server: `192.168.10.4`, listening on UDP/53.
- Internal HTTP Caching Proxy: `192.168.0.2`, listening on TCP/8080.
- Admin workstations: `192.168.0.3`.
- Internal workstations: `192.168.0.4-254`.

Functional requirements:

- External entities on the internet need to access the company HTTP and HTTPS pages and be able to query the company's pubic DNS server and send emails to the public email server.
- Due to the capacity limitations of the ISP pipeline and also the security policy, which requires content filtering in place for that access, the company wants to utilize the caching and content filtering services of the HTTP proxy they have. Due to the variety and dynamic nature of internal clients, the proxy needs to be transparent.
- The company has only one system administrator for managing the servers in the DMZ. Their admin workstation has IP:192.168.0.3. The sysadmin tools to manage the servers in the DMZ are SSH client and SNMP monitoring application.
- Due to the system administrator's specific job responsibilities, they are allowed to access the internet directly as the only exception from the transparent proxy policy

## 2. Security strategy and iptables implementation

### 2.1 Default policy

In order to increase security for the network, we take an aggressive approach, in which we drop all the packets by default and only allow traffic as we need by adding iptables rules explicitly.

The default policy for INPUT, OUTPUT and FORWARD chains can be set as follow:

```bash
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
```

### 2.2 Log dropped packets

All dropped packets should be logged before dropping. Doing this may help us in the process of debugging or identifying any malicious activity occurring within the network. We create a new custom chain named LOG_DROP which will log and then drop the packet. Every time, we need to drop a packet, we only need to jump to this chain, instead of jump to DROP target.

```bash
# Define custom chain LOG_DROP
iptables -N LOG_DROP
iptables -A LOG_DROP -j LOG --log-prefix "Dropped Packets: " --log-level 7
iptables -A LOG_DROP -j DROP
```

### 2.3 Input chain

According to the requirements of Acme Inc., the Linux Gateway plays as a firewall role and there is no server installed in this gateway. Therefore, we simply drop all the incoming packets on the INPUT chain.

```bash
iptables -A INPUT -j LOG_DROP
```

### 2.4 Output chain

We also drop all packets on the OUTPUT chain.

```bash
iptables -A OUTPUT -j LOG_DROP
```

### 2.5 Forward chain

#### 2.5.1 Block common attacks

##### a. Christmas tree packets

Christmas tree packets can be used as a method of TCP/IP stack fingerprinting. By observing the response to the Christmas tree packet, attackers can guess the host's operating system as many operating systems implement their compliance with the Internet Protocol standard in varying or incomplete ways.

```bash
iptables -A FORWARD -p tcp -m tcp --tcp-flags ALL FIN,PSH,URG -j LOG_DROP  
```

##### b. Invalid TCP packets

Invalid TCP packets includes:

- "new" incoming TCP connection packets that doesn't have `SYN` flag set
- "new" state packets that have `SYN` and `ACK` flags set
- TCP packets which have `SYN` and `FIN` flags set
- NULL packets which have no flags set at all

These packets should be dropped as follow:

```bash
iptables -A FORWARD -p tcp ! --syn -m state --state NEW -j LOG_DROP  
iptables -A FORWARD -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j LOG_DROP  
iptables -A FORWARD -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j LOG_DROP  
iptables -A FORWARD -p tcp -m tcp --tcp-flags ALL NONE -j LOG_DROP  
```

##### c. IP spoofing packets

Incoming packets on the WAN interface `eth2` with source IP in ranges such as `0.0.0.0/8`, `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` can be considered as IP spoofing packets because these IP addresses are non-Internet-routable.

```bash
iptables -A FORWARD -i eth2 -s 0.0.0.0/8 -j LOG_DROP  
iptables -A FORWARD -i eth2 -s 10.0.0.0/8 -j LOG_DROP  
iptables -A FORWARD -i eth2 -s 127.0.0.0/8 -j LOG_DROP  
iptables -A FORWARD -i eth2 -s 172.16.0.0/12 -j LOG_DROP  
iptables -A FORWARD -i eth2 -s 192.168.0.0/16 -j LOG_DROP
```

Packets coming in on the WAN interface which have source IP `2.2.2.2` should be dropped as well.

```bash
iptables -A FORWARD -i eth2 -s $eth2_ip -j LOG_DROP
```

#### 2.5.2 Traffic between WAN and DMZ

The packet coming on the WAN interface should be routed to the appropriate server using DNAT target.

```bash
# HTTP and HTTPS server  
iptables -t nat -A PREROUTING -p tcp -i eth2 -d $eth2_ip --dport 80 -j DNAT --to-destination $web_server_ip:80  
iptables -t nat -A PREROUTING -p tcp -i eth2 -d $eth2_ip --dport 443 -j DNAT --to-destination $web_server_ip:443  

# Mail Server  
iptables -t nat -A PREROUTING -p tcp -i eth2 -d $eth2_ip --dport 25 -j DNAT --to-destination $mail_server_ip:25  

# DNS server  
iptables -t nat -A PREROUTING -p udp -i eth2 -d $eth2_ip --dport 53 -j DNAT --to-destination $dns_server_ip:53  
```

Forward the traffic from DMZ `eth1` to WAN `eth2` and only packets which have states RELATED or ESTABLISHED are accepted

```bash
iptables -A FORWARD -i eth1 -o eth2 -m state --state ESTABLISHED,RELATED -j ACCEPT  
```

Forward the traffic from WAN `eth2` to DMZ `eth1`:

```bash
# HTTP, HTTPS server  
iptables -A FORWARD -p tcp -i eth2 -o eth1 -d $web_server_ip -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT  

# Mail server  
iptables -A FORWARD -p tcp -i eth2 -o eth1 -d $mail_server_ip --dport 25 -m state –state NEW,ESTABLISHED -j ACCEPT  

# DNS server  
iptables -A FORWARD -p udp -i eth2 -o eth1 -d $dns_server_ip --dport 53 -m state --state NEW,RELATED -j ACCEPT  
```

All the packets leaving the firewall on the WAN interface must have their source IP addresses changed to the address of the WAN interface. This rule makes sure our network topology is hidden from the outside world.

```bash
iptables -t nat -A POSTROUTING -o eth2 -j MASQUERADE 
```

#### 2.5.3 Traffic between LAN and DMZ

The transparent proxy can be configured as follow:

```bash
iptables -t nat -A PREROUTING -i eth0 -s $proxy_server_ip,$admin_ip -j ACCEPT #1
iptables -t nat -A PREROUTING -p tcp -i eth0 -s 192.168.0.0/24 --dport 80 -j DNAT --to-destination $proxy_server_ip:8080 #2
  
iptables -A FORWARD -p tcp -i eth0 -o eth0 -s 192.168.0.0/24 -d $proxy_server_ip --dport 8080 -j ACCEPT #4
iptables -A FORWARD -p tcp -i eth0 -o eth0 -s $proxy_server_ip --dport 8080 -j ACCEPT #5

iptables -t nat -A POSTROUTING -p tcp -o eth0 -s 192.168.0.0/24 -d $proxy_server_ip --dport 8080 -j MASQUERADE #7
```

In the snippet above, line 1 make sure that the proxy server and the sysadmin workstation can access the internet directly, without being re-routed to the proxy server. Line 4 and 5 allow packets from internal workstations to be able to go to proxy server and packets from proxy server be able to go to the LAN interface. Line 7 causes the reply from the proxy server gets sent back through the LAN interface, instead of directly to the internal workstations.

Forward packets which have states ESTABLISHED or RELATED from the DMZ `eth1` to LAN `eth0`

```bash
iptables -A FORWARD -i eth1 -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT
```

Allow packets from LAN go to DMZ: LAN side should be able to connect with web server on port 80 and 443, Mail server on port 25 and DNS server on port 53. In addition, we also allow the sysadmin workstation to use SSH and SNMP applications to manage the DMZ servers.

```bash
# HTTP, HTTPS server  
iptables -A FORWARD -p tcp -i eth0 -o eth1 -d $web_server_ip -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT  

# Mail server  
iptables -A FORWARD -p tcp -i eth0 -o eth1 -d $mail_server_ip --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT  

# DNS server  
iptables -A FORWARD -p udp -i eth0 -o eth1 -d $dns_server_ip --dport 53 -m state --state NEW,RELATED -j ACCEPT  

# Allow SSH connection from sysadmin workstation  
iptables -A FORWARD -p tcp -i eth0 -o eth1 -s $admin_ip --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT  

# Allow SNMP monitor from sysadmin workstation  
iptables -A FORWARD -p udp -i eth0 -o eth1 -s $admin_ip --dport 161:162 -j ACCEPT  

# Allow ICMP packets from sysadmin workstation  
iptables -A FORWARD -p icmp -i eth0 -o eth1 -s $admin_ip --icmp-type echo-request -j ACCEPT
```

To increase the firewall security, the internal network should be hidden from the DMZ using MASQUERADE target on the POSTROUTING chain:

```bash
iptables -t nat -A POSTROUTING -o eth0 -s 192.168.0.0/24 -j MASQUERADE
```

#### 2.5.4 Traffic between LAN and WAN

Only `ESTABLISHED` or `RELATED` packets are allowed to go from WAN to LAN:

```bash
iptables -A FORWARD -i eth2 -o eth0 -d -m state --state ESTABLISHED,RELATED -j ACCEPT  
```

Forward the HTTP and HTTPS packets from LAN to WAN. It is important to note that the HTTP traffic of internal workstations has been configured to go through HTTP proxy. Therefore, in this case, only the sysadmin workstation and the proxy server can access the Internet directly.

```bash
iptables -A FORWARD -p tcp -i eth0 -o eth2 -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 
```

### 3. Notes

- According to the requirements, we only redirect all the HTTP traffic of the internal workstations to the internal HTTP caching proxy and the HTTPS traffic is out of scope of this project.
- We do not provide remote access to the Linux firewall gateway. It means that one must access the gateway physically in order to configure it.
- The full working script can be found [here](https://github.com/t-ho/dmz-netfilter/blob/master/iptables_rules.sh)
