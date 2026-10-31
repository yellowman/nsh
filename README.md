# nsh

## network shell

---
Chris Cappuccio <chris@nmedia.net>

nsh is a command line interface for network appliances built on OpenBSD.
It replaces ifconfig, sysctl and route with a simple command language of
its own, and it keeps the configuration of the other daemons in the same
place. On an appliance, it takes the place of /etc/netstart and parts of
/etc/rc. With the OpenBSD kernel and the daemons you want to control, it
makes a complete network appliance.

## Components

- **nsh** is the shell. It is a client of nshd: it sends each command to
  nshd, and shows what nshd answers. When nshd does not run, nsh can
  only show its version, and it cannot change the configuration.
- **nshd** holds the configuration and changes the system. At boot it
  makes the saved configuration the running configuration. It runs each
  commit, and it gives each user the permissions of the user's login
  class. nshd is privilege separated: its parent and its system process
  run as root, and each of its other processes runs as a user of its own
  in a chroot(2).
- **nshdeck** is a web configurator for nshd. It runs behind httpd(8),
  and it is optional.
- **bgpnsh** is a BGP looking glass shell for routers that run bgpd(8),
  with the same user interface as nsh. It is an alternative to
  bgplgsh(8).

Root and the members of the group nshadmin may use nshd's read-write
socket, with the permissions of their login class. Any other user may
use its read-only socket, which answers only the shows that anyone may
see.

## Managed services

bgpd, cron (root's crontab), dhcpd, dhcpleased, dhcrelay, dvmrpd,
eigrpd, ftp-proxy, ifstated, inetd, iked, ipsecctl and isakmpd, ldapd,
ldpd, npppd, ntpd, ospfd, ospf6d, pf, rad, relayd, resolvd, ripd,
sasyncd, slaacd, smtpd, snmpd, sshd, tftpd and tftp-proxy. nsh also
keeps the message of the day, /etc/motd.

---

## License

nsh is free software, under BSD-style licenses. The COPYRIGHT file has
the copyright notice of each part.

---

## Documentation

`make install` installs the manual pages nsh(8), nshd(8), nshdeck(8)
and bgpnsh(8). To read nsh's manual page from the system shell:

```shell
man nsh
```

The manual page is also on the project's wiki:
[https://github.com/yellowman/nsh/wiki/NSH-1.2.x-Manual-Page](https://github.com/yellowman/nsh/wiki/NSH-1.2.x-Manual-Page)

### Manual pages from within nsh

nsh's `manual` command shows nsh's manual page. With a term, such as a
command or a kind of interface, it shows the manual page at that term:

```shell
manual [searchterm]
```

For example, to read about VLANs:

```shell
manual vlan
```

To list the terms, type `manual` and a space, and press Tab twice.

---

## Other documentation

- The source code is at https://github.com/yellowman/nsh/.
- The to-do list, with what is done and what is planned, is at
  https://github.com/users/yellowman/projects/1.
- Example configurations, and the mailing list, are at
  https://www.nmedia.net/nsh/.
- Tom Smyth's talk at BSDCan 2024, Supporting Business IT and network
  needs with OpenBSD and NSH: https://www.youtube.com/watch?v=9T9-v5NLjXk
- Tom Smyth's talk at EuroBSDCon 2022, NSH for network administrators:
  https://www.youtube.com/watch?v=WMKxIHaWaG0

---

## Installing nsh

First install OpenBSD. Then install nsh either from the OpenBSD package
or from the source code. Run the commands below as root.

### From the package

The package installs the latest release of nsh:

```shell
pkg_add nsh
```

### From the source code

The source code has the newest development version. nshd needs the
sqlite3 package, and git fetches the source code:

```shell
pkg_add git sqlite3
git clone https://github.com/yellowman/nsh
cd nsh
make
make install
```

`make` builds nsh, nshd, nshdeck and bgpnsh. `make install` installs nsh
and bgpnsh in /usr/local/bin, nshd and nshdeck in /usr/local/sbin, their
manual pages in /usr/local/man, nshdeck's web page in
/var/www/htdocs/nshdeck, and the rc.d(8) scripts that start nshd and
nshdeck in /etc/rc.d. `make static` builds nsh, nshd and bgpnsh
statically linked.

The source code is in these directories:

- nsh/: the files that only nsh builds
- nshd/: the files that only nshd builds
- nshdeck/: nshdeck's files, and its web page in nshdeck/htdocs
- bgpnsh/: the files that only bgpnsh builds
- lib/: the files that more than one of the programs builds or includes
- rc.d/: the rc.d(8) scripts that start nshd and nshdeck
- scripts/: scripts that help to set up a system for nsh

---

## Setting up nshd

nshd must run for nsh to configure the system. Run these steps as root.

1. Create nshd's users and the group nshadmin. nshd runs its show,
   frontend, config and archive processes as users of their own, and
   runs the programs that need no root as _nshcheck.

   ```shell
   groupadd nshadmin
   for u in _nshshow _nshfront _nshconf _nsharc _nshcheck; do
       useradd -L daemon -d /var/empty -s /sbin/nologin $u
   done
   ```

2. Back up the files in /etc that configure the system, the network and
   the daemons.

3. For each daemon that you use, copy its configuration file to
   /var/run, where nshd reads it. The copy's name ends in the number of
   the routing table: .0 for the default routing table. For example:

   ```shell
   cp /etc/pf.conf /var/run/pf.conf.0
   cp /etc/ssh/sshd_config /var/run/sshd.conf.0
   cp /etc/mail/smtpd.conf /var/run/smtpd.conf.0
   chmod 600 /var/run/pf.conf.0 /var/run/sshd.conf.0 /var/run/smtpd.conf.0
   ```

   A daemon without a copy in /var/run has no rules in nsh's
   configuration.

4. Start nshd once by hand, without `-b`, so that it applies no
   configuration:

   ```shell
   /usr/local/sbin/nshd
   ```

5. Run nsh. Check that `show running-config` shows the configuration you
   expect: the interfaces, the routes and each daemon's rules. Then type
   `commit`. Outside configure mode, `commit` saves the running
   configuration as /var/db/nsh/nshrc, the saved configuration.

6. Stop nshd, and have rc(8) start it at each boot. At boot, nshd makes
   the saved configuration the running configuration.

   ```shell
   pkill -x nshd
   rcctl enable nshd
   rcctl start nshd
   ```

7. Restart the system, and check that the running configuration is what
   you expect.

The script scripts/shell/rc.local-nsh-openbsd-integrate.sh does steps 1
to 6 for you. It backs up each daemon's configuration file in
/var/nsh/backup/pre-nsh-config and copies it to /var/run, makes nshd's
users, saves the running configuration, and enables nshd. It asks you
to confirm before it changes anything. Run it as root, in the
scripts/shell directory of the source code, then restart the system:

```shell
cd scripts/shell
sh ./rc.local-nsh-openbsd-integrate.sh
```

nshd can also take its first saved configuration from /etc/nshrc. When
nshd boots and there is no saved configuration, it copies /etc/nshrc to
/var/db/nsh/nshrc. Write the file as `show running-config` shows the
configuration, and make it readable by root alone:

```shell
chmod 600 /etc/nshrc
```

---

## Adding users

Root may do anything in nsh. To let another user use nsh, add a
`login user` line for the user, with a login class, in configure mode,
and commit it. nshd then makes the account, with nsh as its shell and
the group nshadmin.

The line gives the account's password. The simplest way is the word
`plain-text-password`: nsh asks for the password twice, without showing
it, and sends nshd the password's bcrypt hash in place of the word.

```shell
nsh(config-private)# login user nshuser class operator password plain-text-password
New password:
Retype new password:
nsh(config-private)# commit
```

The line can also give a bcrypt hash that you make yourself, with
encrypt(1). A file that `nsh -c` loads must give the hash, because nsh
asks for a password only at a terminal.

```shell
nsh(config-private)# login user nshuser class operator password $2b$10$...
```

An account that you make by hand needs the group nshadmin to use nshd,
and a `login user` line to have a class other than read-only. To add
such an account to nshadmin, and to make nsh its login shell:

```shell
usermod -G nshadmin nshuser
usermod -s /usr/local/bin/nsh nshuser
```

A user can also make nsh their own login shell with chsh(1), if
/usr/local/bin/nsh is listed in /etc/shells:

```shell
chsh -s /usr/local/bin/nsh
```

---

## Setting up nshdeck

nshdeck is optional. To configure the system from a web browser:

1. Create nshdeck's users. _nshweb must be a member of the group
   nshadmin.

   ```shell
   useradd -L daemon -d /var/empty -s /sbin/nologin -G nshadmin _nshweb
   useradd -L daemon -d /var/empty -s /sbin/nologin _nshdeck
   ```

2. Have rc(8) start nshdeck at each boot:

   ```shell
   rcctl enable nshdeck
   rcctl start nshdeck
   ```

3. Add nshdeck's locations to httpd.conf(5). This example from
   nshdeck(8) serves the page at https://router/nshdeck/; use your own
   server name and TLS certificate:

   ```
   server "router" {
       listen on * tls port 443
       connection max request body 3146752
       location "/nshdeck/api/*" {
           fastcgi socket "/run/nshdeck.sock"
       }
       location "/nshdeck/*" {
           root "/htdocs"
       }
   }
   ```

4. Start httpd(8), and have rc(8) start it at each boot:

   ```shell
   rcctl enable httpd
   rcctl start httpd
   ```

Users log in to nshdeck with the name and password of a `login user`
line. Root may not log in to nshdeck.

---

## Feedback

Please send feedback, bug reports and suggestions to the developers on
the mailing list: <nsh@lists.deschutesdigital.com>.
