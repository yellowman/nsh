# nsh 

## network shell

---
Chris Cappuccio <chris@nmedia.net>


NSH is a CLI intended for OpenBSD-based network appliances. It replaces
ifconfig, sysctl and route with its own simple command language, and
encapsulates configuration for other daemons into one place, effectively
replacing /etc/netstart and parts of /etc/rc for appliance-style usage.

## Daemons and services encapsulated by nsh:

bgpd, dhcpd, dhcpleased, dhcrelay, dvmrpd, eigrpd, ftp-proxy, ifstated, inetd, 
iked, ipsecctl, ldapd, ldpd, npppd, ntpd, ospfd, ospf6d, pf, rad, relayd, 
resolvd, ripd, sasyncd, slaacd, smtpd, snmpd, sshd, tftpd, tftp-proxy.

---

## License 

NSH is freely licensed, in the BSD style.

In conjunction with the OpenBSD kernel and the daemons you wish to control,
you have a fully functioning network appliance type of system.

---

## NSH Manual

See [https://github.com/yellowman/nsh/wiki/NSH-Manual-page](https://github.com/yellowman/nsh/wiki/NSH-1.2.x-Manual-Page) or 
nsh.8 manual for detailed installation instructions and command set.

See the to-do list on https://github.com/users/yellowman/projects/1 for 
details on implementation status and future ideas.

See http://github.com/yellowman/nsh/ for current source code repository.
See http://www.nmedia.net/nsh/ for example configurations and mailing
list.

See https://www.youtube.com/watch?v=WMKxIHaWaG0 for an EurobsdCon 2022 
Presentation on NSH for network administrators. 

---

## Quickstart Guide for installing and building **nsh** on an OpenBSD system

1. Install OpenBSD on your system 

2. Install the OpenBSD port of nsh on your system -(this will install the latest nsh release version)

```shell
pkg_add nsh  
```

3. Install git on your system to allow fetching more recent versions of nsh from github

```shell
pkg_add git
```

4. to download the latest development of nsh use git to download the latest nsh repository

```shell
git clone https://github.com/yellowman/nsh
```

5. change directory to the downloaded nsh directory 

```shell
cd nsh
```

6. use make  to build / compile the sources

```shell
make
```

7.  Install the compiled nsh binaries and supporting files (you will need root privileges to do this).

```shell
make install
```

8. To have nsh take over the configuration of a system a number of steps that need to be carried out such as


9. Backup configuration of system, daemons and network in /etc 

10. Copy the configuration files to /var/run/example-configfilename.0  (the .0 file extension) implies running in the default rdomain / rtable (rdomain 0)

11. save the running config to /etc/nshrc

12. secure the /etc/nshrc file so that world cannot read, write or execute it . 

13. configure the system to run nsh -i /etc/nshrc  either adding a line to /etc/rc.local or using an rccctl script for nsh.

For the users convenience, the above steps (9-13) can be largely automated by running  the **rc.local-nsh-openbsd-integrate.sh** script and following on screen instructions.

```shell
cd nsh
cd scripts
cd shell
chmod 700 rc.local-nsh-openbsd-integrate.sh
./rc.local-nsh-openbsd-integrate.sh

```
14. once configuration has been imported, restart the system and verify nsh config is running as expected.

15. Setting NSH as the default shell for a user

- Login as the user
- locate nsh binary, it is usually in /usr/local/bin/nsh
- at the command prompt run chsh -s command to set the shell to path to the nsh binary
```shell
chsh -s /usr/local/bin/nsh
```

16. please provide feedback , bug repots and suggestions to the developers on	our mailing list  <nsh@lists.deschutesdigital.com> .
    


    
