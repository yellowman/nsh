
class: center, middle

# NSH Basics
  
  
### Section 1

---
## Unix Based Routers with a Unified Config.

- Some people are not comfortable with Unix Command line 
- Some router clis are not much better
- However some modern router clis are significatnly easier to use.
- Staff Training,  how many staff know Unix ?
  - Cli skills level ? 
  - Unix skills level ?
- Linux BSD and other systems have inconsistent configuration / command syntax 

---
## enter NSH  *N*etwork *SH*ell & its goals

- Shell and interpreter for configuring OpenBSD as a network appliance
- Guide the user in configuration with 
  - brief command help with help command or ?
  - double <tab> command line completion
  - manual command to provide more detail in an easy to navigate help system
- allow a competent network engineer to harness the full power of OpenBSD without prior Unix Experience. 
- keep configuration minimal (hide system default config values)
- unified configuration one configuration file to control all aspects of the router.
- intuitive configuration language similar to that commonly deployed commercial routers / switch
- dont rewrite / translate daemon configuration  syntax (wrap around existing config systnax) 
	
---
## NSH  *N*etwork *SH*ell History

Project started by Chris Cappuccio in 2002

- Developed on a part time basis over the years
- Tom Smyth joined the project as OpenBSD NSH package maintainer in March 2021
- Stefan Sperling joined the project in January 2023

---
## Getting Started with NSH - *N*etwork *SH*ell (Interactively) 

NSH can be set as a users default shell or started by executing nsh
- NSH has 3 main interactive modes  
   - unprivileged mode is entered if a standard user executes nsh
     - allows user to run basic diagnostic commands such as ping tracert, show route, show arp
   - enable privileged mode is entered if the root user executes nsh or if a normal user enters the command 'enable'
     - (read config including sensitive config, but config cannot be modified (safety))
   - privileged config mode is entered from privileged mode by entering the command 'configure'
     - (modify configuration) 
	
```shell
nsh# nsh
% NSH v1.1
nsh/enable 
nsh(p)/configure 
nsh(config-p)/exit
nsh(p)/disable 
nsh/
```
- NB the different prompts for different NSH modes!  	

---
## Getting Started with NSH - *N*etwork *SH*ell non interactive use

- NSH can be used to load configuration from a file (batch changes/ automation)
- update config - execute a series of NSH commands from a file 

```shell
#nsh –c /home/config-script-to-update-config
```
- Initialise config (startup config)
```shell
#nsh –i /etc/nshrc
```

---
## Getting Started with NSH - command help

- command ? - display brief command help for "command"

```shell
nsh(config-p)/pf ?
% Arguments may be abbreviated

   enable       enable pf firewall 
   disable      disable pf firewall 
   edit         edit, test and stage firewall rules 
   check-config test and display staged firewall rules 
   reload       test and apply staged firewall rules 
nsh(config-p)/	
```
- command [tab] [tab]  displays a horisontal list of command options for "command"

```shell
nsh(config-p)/pf 
check-config	disable		edit		enable		reload
nsh(config-p)/
```

---
## Getting Started with NSH - Read The Fine Manual

- The manual is accessible within nsh with the manual command

```shell
     manual [search tag]
```
- Display the nsh manual page.  If a search tag is specified then jump to
     the first section matching this tag if one or more matching tags exist.
- Alterntively one can access the nsh manual page in  other OpenBSD shells with the man command 

```shell
 man nsh
```

---
## Getting Started with NSH - manual [command]

- manual command - opens the nsh manual at the correct page for "command"
- makes use of search tags in mandoc
- user can jump forward to next search tag  with [t]
- user can jump back to previous search tag with [shift] [T]
- command [tab] [tab]  displays a horisontal list of command options 
  for "command"	

- E.g. manual bridge 
```shell
nsh(bridge-bridge101)/manual bridge
```

---
## Getting Started with NSH - manual bridge command output
 
```shell
    [no] bridge [bridge-name]
     Modify bridge configuration on the named bridge or layer 2 forwarding
     interfaces such as, bridge(4), veb(4), tpmr(4).  See also OpenBSD manual
     pages for bridge(4), veb(4), tpmr(4) and ifconfig(8) (accessible via the
     following nsh commands):

           !man bridge
           !man ifconfig
     -   e.g. configure bridge settings on bridge1, and display bridge          
         configuration help.
     E.g show available bridge configuration commands.

           nsh(config-p)/bridge bridge100
           nsh(bridge-bridge100)/?
           % Commands may be abbreviated.
           % Type 'exit' at a prompt to leave bridge configuration mode.
           % Bridge configuration commands are:

             description   Bridge description                                   
             member        Bridge member(s)
             span          Bridge spanning port(s)
```

---
## Getting Started with NSH - manual command - [tab] [tab] 
-Display all available search terms or commands in manual 

```shell
nsh(config-p)/manual 
ah		ftp-proxy	ldp		protected	span
arp		group		ldpd		quit		ssh
autoconf	help		lladdr		rdomain		switch
bgp		hostname	macaddress	reboot		switchport
bgpctl		hsrp		manual		relay		sync
bgpd		icmp		mbuf		relayd		syncdev
bridge		ifstate		monitor		resolv		tcp
bridgeport	ifstated	mpls		resolv.conf	telnet
carp		igmp		multicast	rip		tftp
config		ike		nameserver	ripd		tftp-proxy
configure	iked		ndp		route		tpmr
crontab		ikev2		nppp		route6		traceroute
dhcp		inetd		ntpd		sadb		unsetenv
dhcpd		interface	ospf		sasync		veb
dvmrpd		isakmpd		patch		setenv		vpls
eigrp		kernel		pfsync		shell		vxlan
enable		l2vpn		ping6		smtp		wg
esp		label		pipex		smtpd		wireguard
flow		ldap		powerdown	snmp		write-config
flush		ldapd		privileged	snmpd		<cr>
nsh(config-p)/manual 
```

---
## Getting Started with NSH - manual Command - search tags

- user can jump forward to next search tag  with [t]
- user can jump back to previous search tag with [shift] [T]
		
```shell 
     show bridge [bridge-interface | veb-interace | tpmr-interface]

     Without specifying an argument, it displays all layer2 forwarding devices
     configured on the system, and all members of each layer2 forwarding
     device, and any description of the layer2 forwarding device.  Layer 2
     forwarding devices supported by this command include bridge(4) standard
     bridge, veb(4) virtual ethernet bridge and the tpmr(4) two port mac relay
     device.
```

---
##    NSH - manual Command  search tag  continued

```shell
     e.g. Display all layer2 forwarding devices and their member ports

           nsh(p)/show bridge
           % Bridge    Status  Member Interfaces
             bridge1   down
                       Description: -
             bridge100 up      vlan100
                       Description: Tom-Smyths-Bridge
             veb200    up      vlan200
                       Description: Chris-Cappuccios-Bridge
             tpmr102   up      vether1102 vether2102
                       Description: dlg-bridge
           nsh(p)/
     e.g. Display the information the tpmr102 layer2 forwarding device
	
```

---
## Getting Started with NSH - show command 

- show commands are read only, they do not alter the state of the system,
	they are intended to give the user full visibility on selected aspects
	of the state of the system.
- E.g. show arp  - displays Address Resolution Protocol 
	
```shell
nsh/show arp
Host                                 Ethernet Address   Netif Expire     Flags
10.0.2.2                             52:54:00:12:35:02    em0 12m37s     
10.0.2.15                            08:00:27:bd:cb:77    em0 permanent  l
```

---
## Getting Started with NSH - show route Command 

-E.g. show route display the IP route table of the system 	

```shell
nsh/show route
Flags: U - up, G - gateway, H - host, L - link layer, R - reject (unreachable),
       D - dynamic, S - static, T - MPLS, c - CLONED, l - LOCAL

% IPv4:
Destination        Gateway            Flags    Refs      Use    Mtu  Interface
0.0.0.0/0          10.0.2.2           UGS         6      881      -   em0
224.0.0.0/4        127.0.0.1          URS         0       53  32768   lo0
10.0.2.0/24        10.0.2.15          U           1        0      -   em0
10.0.2.2           52:54:00:12:35:02  UHLc        1       17      -   em0
10.0.2.15          08:00:27:bd:cb:77  UHL         0       43      -   em0
10.0.2.255         10.0.2.15          UH          0        0      -   em0
127.0.0.0/8        127.0.0.1          UGRS        0        0  32768   lo0
127.0.0.1          127.0.0.1          UH          1        2  32768   lo0

```

---
## Getting Started with NSH - brief diagnostics

- NSH user can set the desired verbosity levels of any command run after
	setting the verbosity
- NSH displays brief diagnostics by default.
```Shell
nsh/no verbose 
% Diagnostic mode disabled
```
	
```Shell
nsh/show interface em0
% em0
  Interface is up (last change 13:42:23), protocol is up
  Interface type Ethernet (Broadcast), hardware address 08:00:27:bd:cb:77
  Media type autoselect (1000baseT full-duplex), status active
  Internet address 10.0.2.15/24
  rdomain 0, MTU 1500 bytes (hardmtu 16110), Line Rate 1000 Mbps
  40634 packets input, 26668678 bytes, 0 errors, 0 drops
  32334 packets output, 12272854 bytes, 0 errors, 0 unsupported
  656 input, 379 output (average bytes/packet)
  0 collisions
```

---
## Getting Started with NSH - verbose diagnostics

- NSH user can use the verbose command to increase the level of detai displayed
	by subsequent nsh commands.
	 
```Shell
nsh/verbose
% Diagnostic mode enabled
```
```Shell
nsh/show interface em0
% em0
  Interface is up (last change 13:42:15), protocol is up
  Interface type Ethernet (Broadcast), hardware address 08:00:27:bd:cb:77
  Media type autoselect (1000baseT full-duplex), status active
  Internet address 10.0.2.15/24
  rdomain 0, MTU 1500 bytes (hardmtu 16110), Line Rate 1000 Mbps
  40632 packets input, 26668498 bytes, 0 errors, 0 drops
  32332 packets output, 12272674 bytes, 0 errors, 0 unsupported
  656 input, 379 output (average bytes/packet)
  0 collisions
  Flags:
    <UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
  Hardware features:
    <CSUM_TCPv4,CSUM_UDPv4,VLAN_MTU,VLAN_HWTAGGING>
  Supported media types on em0:
    media 10baseT
    media 10baseT, mediaopt full-duplex
    media 100baseTX
    media 100baseTX, mediaopt full-duplex
    media 1000baseT, mediaopt full-duplex
    media 1000baseT
    media autoselect
```
---
## Getting Started with NSH - show monitor 

- show monitor is the implementation of route monitor in OpenBSD which displays any changes to the 
	    RIB Routing Information Base on the system
			
```shell
nsh/show monitor 
% Entering monitor mode ... press ENTER or ^C to leave ...
% Message of size 192 on Tue May 23 12:33:35 2023
% RTM_ADD: Add Route: len 192, table 0, pid: 92724, seq 1, errno 0, flags:<UP,GATEWAY,DONE,STATIC>
% locks:  inits: 
% sockaddrs: <DST,GATEWAY,NETMASK,IFP,IFA>
 100.64.0.0 127.0.0.1 255.192.0.0 lo0 127.0.0.1
% Message of size 192 on Tue May 23 12:33:48 2023
% RTM_DELETE: Delete Route: len 192, table 0, pid: 83139, seq 1, errno 0, flags:<GATEWAY,DONE,STATIC>
% locks:  inits: 
% sockaddrs: <DST,GATEWAY,NETMASK,IFP,IFA>
 100.64.0.0 127.0.0.1 255.192.0.0 lo0 127.0.0.1
^C% select: Interrupted system call
```
- E.g. above shows that an admin was adding and then removing a static route to 100.64.0.0/10 pointing to the loopack	  
---	
## Getting Started with NSH - config contexts - global context

- global configuration context contains configuration items that modify the sytem configuration such as:
	- hostname
 	- enabling daemons such as
		- sshd
  		- snmpd
		- relayd		 	 

```shell
nsh(config-p)/show run
!
hostname nsh
```
---
## Getting Started with NSH - config contexts - interface context

-  interface / bridge configuration context -allows the user query and change what is setup on the
-  interface or bridge
-  allows for unique per interface configuration
-  similar behavior to other router / switch operatingg systems that are widely deployed.

```shell
nsh(config-p)/interface vio0
nsh(interface-vio0)/show active-config 
interface vio0
 group egress
 autoconf4
!
```
---
## Getting Started with NSH - show active-config

- One of the Design goals of NSH to have all config in one location
- Large configurations can be challenging when a user wants to just check and modify a small part of the config
- The show active-config command allows the user to display configuration on the currently active bridge or interface
	- before configuration changes are made
	- after configuration changes are entered
	- validate current context and configuration 
```shell
nsh(config-p)/interface em0
nsh(interface-em0)/show active-config 
interface em0
 group egress
 autoconf4
!
```
- The show active-config command only displays the active configuration in the currently selected interface or bridge
- This saves alot of scrolling on large configuratons!
---
## Getting Started with NSH - show active-config
- show active configuration works in bridge context as well
  
```shell
nsh(config-p)/interface bridge101
nsh(bridge-bridge101)/show active-config
bridge bridge101
 description new bridge for nshtutorial demo
 group bridge
 shutdown
!
```
---

## Getting Started with NSH - show ip

- Display a list of configured IP addresses
	- on what interfaces they are configured
 	- on what rdomain are they are configured
	- how the IP address was configured 
```shell
nsh(config-p)/show ip 
Address    Interface  RDomain  Type
10.0.2.15  em0              0  dhcp
127.0.0.1  lo0              0  static
::1        lo0              0  static
fe80:4::1  lo0              0  link-local
nsh(config-p)/
```
---
## Getting Started with NSH - show autoconf

- Displays a list dynamic / autoconfigured IP addresses,
	- what interfaces they are bound to
 	- what other  configuration was imported
  		- default gateway
		- dns servers 	 
  	- and where the configuration was pulled from
```shell
nsh(config-p)/show autoconf
em0 [Bound]
	inet 10.0.2.15 netmask 255.255.255.0
	default gateway 10.0.2.2
	nameservers 192.168.67.221
	lease 23 hours
	dhcp server 10.0.2.2
nsh(config-p)/
```
---
## Getting Started with NSH - Firewall configuration - pf command 

- Firewall can be configured in NSH with pf command

```shell
nsh(config-p)/pf ?
% Arguments may be abbreviated

   enable       enable pf firewall 
   disable      disable pf firewall 
   edit         edit, test and stage firewall rules 
   check-config test and display staged firewall rules 
   reload       test and apply staged firewall rules 
nsh(config-p)/
```
---
## Getting Started with NSH - Firewall configuration - pf edit

- pf edit command will edit the firewall with your preferred editor

```shell
nsh(config-p)/pf edit
/var/run/pf.conf.0 is empty. Load an example config? [Y/n]
```
- If there was no firewall rules previously edited in NSH you will be asked,  do you want to load an example configuration
- example config files are generally copied from /etc/examples
- it is recommended to load an example to get you started, and edit to suit your needs.
---

## Getting Started with NSH - Firewall configuration - pf edit
```shell
       $OpenBSD: pf.conf,v 1.4 2018/07/10 19:28:35 henning Exp $
#
# See pf.conf(5) for syntax and examples.
# Remember to set net.inet.ip.forwarding=1 and/or net.inet6.ip6.forwarding=1
# in /etc/sysctl.conf if packets are to be forwarded between interfaces.

# increase default state limit from 100'000 states on busy systems
#set limit states 500000

set skip on lo

# filter rules and anchor for ftp-proxy(8)
#anchor "ftp-proxy/*"
#pass in quick inet proto tcp to port ftp divert-to 127.0.0.1 port 8021

pass            # establish keep-state

```
- Default pf rules as loaded by NSH
- Editor combined with pfctl is used to minimise code base of NSH
- Has an advantage of allowing users to edit config of multiple interdependent daemons and config before activating them
---

## Getting Started with NSH - Firewall configuration - pf edit

- General configuration for pf

- Useful for debugging, applying default timeout values, etc.

```shell
#       $OpenBSD: pf.conf,v 1.4 2018/07/10 19:28:35 henning Exp $
#
# See pf.conf(5) for syntax and examples.
# Remember to set net.inet.ip.forwarding=1 and/or net.inet6.ip6.forwarding=1
# in /etc/sysctl.conf if packets are to be forwarded between interfaces.
INSERT BAD SYNTAX Error
# increase default state limit from 100'000 states on busy systems
#set limit states 500000
```
- NSH tests the config when saving the configuration on exiting the editor

```shell
/var/run/pf.conf.0:6: syntax error
nsh(config-p)/
```

---

## Getting Started with NSH - Firewall configuration - pf check-config -error 

- you can run a check of the staged pf with the command
- pf check-config 
```shell
nsh(config-p)/pf check-config 
Loaded 714 passive OS fingerprints
/var/run/pf.conf.0:6: syntax error
set skip on { lo }
nsh(config-p)/
```
- This is the equivalent of the pfctl -nvv command
- Checks the staged config (not the active config)

## Getting Started with NSH - Firewall configuration - pf check-config -error

- Shows config until the first error is encountered

```shell
ksh# pfctl -nvvf /etc/pf.conf
Loaded 714 passive OS fingerprints
/var/run/pf.conf.0:6: syntax error
set skip on { lo }
ksh#
```
- Where was the error  in the config ? 
---

## Getting Started with NSH - Firewall configuration - pf check-config -success

- pf check-config 
- If syntax check passes it will display the list of rules in order.
  
```shell
nsh(config-p)/pf check-config
Loaded 714 passive OS fingerprints
set skip on { lo }
@0 block return all
@1 pass all flags S/SA
@2 block return in on ! lo0 proto tcp from any to any port 6000:6010

```
---

