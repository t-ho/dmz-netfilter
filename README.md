# DMZ Design Using Linux Netfilter

## Scenario

[![network-infrastructure-diagram](https://raw.githubusercontent.com/t-ho/dmz-netfilter/master/assets/diagram.png)](https://github.com/t-ho/dmz-netfilter)

The network infrastructure has the following details:

- Linux Gateway with three ethernet interfaces: eth0: 192.168.0.1 (attached to the internal LAN:192.168.0.0/24); eth1: 192.168.10.1 (attached to the DMZ segment: 192.168.10.0/24) and eth2:2.2.2.2 (attached to the ISP provider network with default GW: 2.2.2.1).
- Mail server:192.168.10.2, listening on TCP/25.
- Web Server: 192.168.10.3, running Apache on ports 80 and 443.
- DNS server: 192.168.10.4, listening on UDP/53.
- Internal HTTP Caching Proxy: 192.168.0.2, listening on TCP/8080.
- Admin workstations: 192.168.0.3.
- Internal workstations: 192.168.0.4-254.

Functional requirements:

- External entities on the internet need to access the company HTTP and HTTPS pages and be able to query the company's pubic DNS server and send emails to the public email server.
- Due to the capacity limitations of the ISP pipeline and also the security policy, which requires content filtering in place for that access, the company wants to utilize the caching and content filtering services of the HTTP proxy they have. Due to the variety and dynamic nature of internal clients, the proxy needs to be transparent.
- The company has only one system administrator for managing the servers in the DMZ. Their admin workstation has IP:192.168.0.3. The sysadmin tools to manage the servers in the DMZ are SSH client and SNMP monitoring application.
- Due to the system administrator's specific job responsibilities, they are allowed to access the internet directly as the only exception from the transparent proxy policy
