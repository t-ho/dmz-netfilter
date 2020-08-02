eth0_ip=192.168.0.1
eth1_ip=192.168.10.1
eth2_ip=2.2.2.2
mail_server_ip=192.168.10.2
web_server_ip=192.168.10.3
dns_server_ip=192.168.10.4
proxy_server_ip=192.168.0.2
admin_ip=192.168.0.3

# Enable IP forwarding

echo 1 > /proc/sys/net/ipv4/ip_forward   

# Flush active rules and custom tables before starting   
iptables -F 
iptables -X 
iptables -t nat -F

# Set default policies   
iptables -P INPUT DROP
iptables -P FORWARD DROP   
iptables -P OUTPUT DROP   

# Define custom chain LOG_DROP   
iptables -N LOG_DROP   
iptables -A LOG_DROP -j LOG --log-prefix "Dropped Packets: " --log-level 7   
iptables -A LOG_DROP -j DROP   

# PREROUTING chain   
# Web server   
iptables -t nat -A PREROUTING -p tcp -i eth2 -d $eth2_ip --dport 80 -j DNAT --to-destination $web_server_ip:80   
iptables -t nat -A PREROUTING -p tcp -i eth2 -d $eth2_ip --dport 443 -j DNAT --to-destination $web_server_ip:443   

# Mail Server   
iptables -t nat -A PREROUTING -p tcp -i eth2 -d $eth2_ip --dport 25 -j DNAT --to-destination $mail_server_ip:25   

# DNS server   
iptables -t nat -A PREROUTING -p udp -i eth2 -d $eth2_ip --dport 53 -j DNAT --to-destination $dns_server_ip:53   

# Route the HTTP traffic of internal workstations (except proxy server and sysadmin) to proxy server   
iptables -t nat -A PREROUTING -i eth0 -s $proxy_server_ip,$admin_ip -j ACCEPT   
iptables -t nat -A PREROUTING -p tcp -i eth0 -s 192.168.0.0/24 --dport 80 -j DNAT --to-destination $proxy_server_ip:8080   

# INPUT chain   
iptables -A INPUT -j LOG_DROP   

# OUTPUT chain   
iptables -A OUTPUT -j LOG_DROP   

# FORWARD chain   
# Drop bad packets   
# Christmas tree packets   
iptables -A FORWARD -p tcp -m tcp --tcp-flags ALL FIN,PSH,URG -j LOG_DROP   

# Invalid TCP packets   
# New incoming TCP connection packets without SYN flag set   
iptables -A FORWARD -p tcp ! --syn -m state --state NEW -j LOG_DROP   

# New state packet with SYN,ACK set   
iptables -A FORWARD -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j LOG_DROP   

# TCP packets with SYN,FIN flag set   
iptables -A FORWARD -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j LOG_DROP   

# Null packets   
iptables -A FORWARD -p tcp -m tcp --tcp-flags ALL NONE -j LOG_DROP   

# Drop spoofing packets coming on the WAN interface   
iptables -A FORWARD -i eth2 -s 0.0.0.0/8 -j LOG_DROP   
iptables -A FORWARD -i eth2 -s 10.0.0.0/8 -j LOG_DROP   
iptables -A FORWARD -i eth2 -s 127.0.0.0/8 -j LOG_DROP   
iptables -A FORWARD -i eth2 -s 172.16.0.0/12 -j LOG_DROP   
iptables -A FORWARD -i eth2 -s 192.168.0.0/16 -j LOG_DROP   
iptables -A FORWARD -i eth2 -s $eth2_ip -j LOG_DROP   

# Only accept packets in ESTABLISHED or RELATED state from DMZ to WAN   
iptables -A FORWARD -i eth1 -o eth2 -m state --state ESTABLISHED,RELATED -j ACCEPT   

# Only accept packets in ESTABLISHED or RELATED state from DMZ to LAN   
iptables -A FORWARD -i eth1 -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT   

# Only accept packets in ESTABLISHED or RELATED state from WAN to LAN   
iptables -A FORWARD -i eth2 -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT   

# From WAN to DMZ   
# HTTP, HTTPS server   
iptables -A FORWARD -p tcp -i eth2 -o eth1 -d $web_server_ip -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT   

# Mail server   
iptables -A FORWARD -p tcp -i eth2 -o eth1 -d $mail_server_ip --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT   

# DNS server   
iptables -A FORWARD -p udp -i eth2 -o eth1 -d $dns_server_ip --dport 53 -m state --state NEW,RELATED -j ACCEPT   

# From LAN to DMZ   
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
iptables -A FORWARD -p icmp -i eth0 -o eth1 -s $admin_ip --icmp-type echo-request -j ACCEPT 

# Allow traffic between internal workstations and proxy   
iptables -A FORWARD -p tcp -i eth0 -o eth0 -s 192.168.0.0/24 -d $proxy_server_ip --dport 8080 -j ACCEPT   

# Allow traffic between proxy server and interal workstations   
iptables -A FORWARD -p tcp -i eth0 -o eth0 -s $proxy_server_ip --dport 8080 -j ACCEPT   

# From LAN to WAN   
iptables -A FORWARD -p tcp -i eth0 -o eth2 -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT   

# POSTROUTING chain   
iptables -t nat -A POSTROUTING -o eth2 -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth0 -s 192.168.0.0/24 -j MASQUERADE
