#!/bin/sh -
#This script integrates nsh with OpenBSD. To import the daemons'
#configuration, it copies their files; it does not move them.
#With current nsh setup it is possible that a user would be confused
#between default locations of daemon config files and the nsh config file
#locations.
#this script assumes a basic openBSD installation with all daemons running
#in a single rdomain.
#Then it sets up nshd, which holds nsh's configuration: it makes nshd's
#users and the group nshadmin, starts nshd once without booting, has nsh
#save the running configuration with commit, and has rc start nshd at
#each boot.

dflt='No'

#check if user is root
if [ $(id -u) != 0 ];
then
        echo "Must be run as root"
        exit
else
        #ask user do they want to continue
        #default is No
        echo "This script copies the daemons' configuration files from /etc"
        echo "to /var/run, where nshd reads them, and sets up nshd. It suits a"
        echo "typical OpenBSD system with one routing domain. With an unusual"
        echo "configuration, such as several routing domains, read the script"
        echo "before you continue."
        read input?"Do you want to continue? (Yes/No) [${dflt}] "

        if [ -z "${input}" ]; then input="${dflt}"; fi
        if [ "${input}" = 'Yes' ] || [ "${input}" = 'yes' ];
        then
                test -d /var/nsh/backup/pre-nsh-config && echo pre-nsh-config exists already && exit
                test -f /var/db/nsh/nshrc && echo nsh-saved-config exists already && exit

                mkdir -p /var/nsh/backup/pre-nsh-config

                #remove world permissions from created directories
                chmod -R 750 /var/nsh
                chown -R root /var/nsh
                chgrp -R wheel /var/nsh
                #chmod 750 /var/nsh/backup
                #chmod 750 /var/nsh/backup/pre-nsh-config

                #checks if file exists
                #makes a copy and moves conf file
                #secures file
                pf='/etc/pf.conf'
                if [ -f $pf ]; then
                        cp /etc/pf.conf /var/nsh/backup/pre-nsh-config/
                        cp /etc/pf.conf /var/run/pf.conf.0
                        chown root /var/run/pf.conf.0
                        chgrp wheel /var/run/pf.conf.0
                        chmod 660 /var/run/pf.conf.0
                else
                        echo etc-pf does not exist, not importing!
                fi

                ipsec='/etc/ipsec.conf'
                if [ -f $ipsec ]; then
                        cp /etc/ipsec.conf /var/nsh/backup/pre-nsh-config/
                        cp /etc/ipsec.conf /var/run/ipsec.conf.0
                        chown root /var/run/ipsec.conf.0
                        chgrp wheel /var/run/ipsec.conf.0
                        chmod 660 /var/run/ipsec.conf.0
                else
                        echo etc-ipsec does not exist, not importing!
                fi

                bgpd='/etc/bgpd.conf'
                if [ -f $bgpd ]; then
                        cp /etc/bgpd.conf /var/nsh/backup/pre-nsh-config/
                        cp /etc/bgpd.conf /var/run/bgpd.conf.0
                        chown root /var/run/bgpd.conf.0
                        chgrp wheel /var/run/bgpd.conf.0
                        chmod 660 /var/run/bgpd.conf.0
                else
                        echo etc-bgpd does not exist, not importing!
                fi

                ospfd='/etc/ospfd.conf'
                if [ -f $ospfd ]; then
                        cp /etc/ospfd.conf /var/nsh/backup/pre-nsh-config/
                        cp /etc/ospfd.conf /var/run/ospfd.conf.0
                        chown root /var/run/ospfd.conf.0
                        chgrp wheel /var/run/ospfd.conf.0
                        chmod 660 /var/run/ospfd.conf.0
                else
                        echo etc-ospfd does not exist, not importing!
                fi


                ospf6d='/etc/ospf6d.conf'
                if [ -f $ospf6d ]; then
                        cp /etc/ospf6d.conf /var/nsh/backup/pre-nsh-config/
                        cp /etc/ospf6d.conf /var/run/ospf6d.conf.0
                        chown root /var/run/ospf6d.conf.0
                        chgrp wheel /var/run/ospf6d.conf.0
                        chmod 660 /var/run/ospf6d.conf.0
                else
                        echo etc-ospf6d does not exist, not importing!

                fi
                dhcpd='/etc/dhcpd.conf'
                if [ -f $dhcpd ]; then
                        cp /etc/dhcpd.conf /var/nsh/backup/pre-nsh-config/
                        cp /etc/dhcpd.conf /var/run/dhcpd.conf.0
                        chown root /var/run/dhcpd.conf.0
                        chgrp wheel /var/run/dhcpd.conf.0
                        chmod 660 /var/run/dhcpd.conf.0
                else
                        echo etc-dhcpd does not exist, not importing!
                fi

                ntpd='/etc/ntpd.conf'
                if [ -f $ntpd ]; then
                        cp /etc/ntpd.conf /var/nsh/backup/pre-nsh-config/
                        cp /etc/ntpd.conf /var/run/ntpd.conf.0
                        chown root /var/run/ntpd.conf.0
                        chgrp wheel /var/run/ntpd.conf.0
                        chmod 660 /var/run/ntpd.conf.0
                else
                        echo etc-ntpd does not exist, not importing!
                fi

                sshd_config='/etc/ssh/sshd_config'
                if [ -f $sshd_config ]; then
                        cp /etc/ssh/sshd_config /var/nsh/backup/pre-nsh-config/
                        cp /etc/ssh/sshd_config /var/run/sshd.conf.0
                        chown root /var/run/sshd.conf.0
                        chgrp wheel /var/run/sshd.conf.0
                        chmod 660 /var/run/sshd.conf.0
                else
                        echo etc-ssh_config does not exist, not importing!
                fi

                eigrpd='/etc/eigrpd.conf'
                if [ -f $eigrpd ]; then
                        cp /etc/eigrpd.conf /var/nsh/backup/pre-nsh-config/
                        cp /etc/eigrpd.conf /var/run/eigrpd.conf.0
                        chown root /var/run/eigrpd.conf.0
                        chgrp wheel /var/run/eigrpd.conf.0
                        chmod 660 /var/run/eigrpd.conf.0
                else
                        echo etc-eigrpd does not exist, not importing!
                fi

                relayd='/etc/relayd.conf'
                if [ -f $relayd ]; then
                        cp /etc/relayd.conf /var/nsh/backup/pre-nsh-config/
                        cp /etc/relayd.conf /var/run/relayd.conf.0
                        chown root /var/run/relayd.conf.0
                        chgrp wheel /var/run/relayd.conf.0
                        chmod 660 /var/run/relayd.conf.0
                else
                        echo etc-relayd does not exist, not importing!
                fi

                ripd='/etc/ripd.conf'
                if [ -f $ripd ]; then
                        cp /etc/ripd.conf /var/nsh/backup/pre-nsh-config/
                        cp /etc/ripd.conf /var/run/ripd.conf.0
                        chown root /var/run/ripd.conf.0
                        chgrp wheel /var/run/ripd.conf.0
                        chmod 660 /var/run/ripd.conf.0
                else
                        echo etc-ripd does not exist, not importing!
                fi

                ldpd='/etc/ldpd.conf'
                if [ -f $ldpd ]; then
                        cp /etc/ldpd.conf /var/nsh/backup/pre-nsh-config/
                        cp /etc/ldpd.conf /var/run/ldpd.conf.0
                        chown root /var/run/ldpd.conf.0
                        chgrp wheel /var/run/ldpd.conf.0
                        chmod 660 /var/run/ldpd.conf.0
                else
                        echo etc-ldpd does not exist, not importing!
                fi

                iked='/etc/iked.conf'
                if [ -f $iked ]; then
                        cp /etc/iked.conf /var/nsh/backup/pre-nsh-config/
                        cp /etc/iked.conf /var/run/iked.conf.0
                        chown root /var/run/iked.conf.0
                        chgrp wheel /var/run/iked.conf.0
                        chmod 660 /var/run/iked.conf.0
                else
                        echo etc-iked does not exist, not importing!
                fi

                snmpd='/etc/snmpd.conf'
                if [ -f $snmpd ]; then
                        cp /etc/snmpd.conf /var/nsh/backup/pre-nsh-config/
                        cp /etc/snmpd.conf /var/run/snmpd.conf.0
                        chown root /var/run/snmpd.conf.0
                        chgrp wheel /var/run/snmpd.conf.0
                        chmod 660 /var/run/snmpd.conf.0
                else
                        echo etc-snmpd does not exist, not importing!
                fi

                ldapd='/etc/ldapd.conf'
                if [ -f $ldapd ]; then
                        cp /etc/ldapd.conf /var/nsh/backup/pre-nsh-config/
                        cp /etc/ldapd.conf /var/run/ldapd.conf.0
                        chown root /var/run/ldapd.conf.0
                        chgrp wheel /var/run/ldapd.conf.0
                        chmod 660 /var/run/ldapd.conf.0
                else
                        echo etc-ldapd does not exist, not importing!
                fi

                resolv='/etc/resolv.conf'
                if [ -f $resolv ]; then
                        cp /etc/resolv.conf /var/nsh/backup/pre-nsh-config/

                else
                        echo etc-resolv does not exist, not backing up!
                fi

                motd='/etc/motd'
                if [ -f $motd ]; then
                        cp /etc/motd /var/nsh/backup/pre-nsh-config/
                        cp /etc/motd /var/run/motd.0
                        echo nsh has been integrated with this OpenBSD install by copying >>/var/run/motd.0
                        echo configs from \/etc\/  to \/var/run\/ >>/var/run/motd.0
                        echo daemons that are started using rcctl openBSD will continue to use >>/var/run/motd.0
                        echo the config files located in \/etc\/ >>/var/run/motd.0
                        echo daemons started and managed by nsh will >>/var/run/motd.0
                        echo use the files located in \/var\/run\/ >>/var/run/motd.0
                        chown root /var/run/motd.0
                        chgrp wheel /var/run/motd.0
                        chmod 664 /var/run/motd.0
                else
                        echo etc-motd does not exist, not importing!
                fi

                smtpd='/etc/mail/smtpd.conf'
                if [ -f $smtpd ]; then
                        cp /etc/mail/smtpd.conf /var/nsh/backup/pre-nsh-config/
                        cp /etc/mail/smtpd.conf /var/run/smtpd.conf.0
                        chown root /var/run/smtpd.conf.0
                        chgrp wheel /var/run/smtpd.conf.0
                        chmod 660 /var/run/smtpd.conf.0
                else
                        echo etc-smtpd does not exist, not importing!
                fi

                dvmrpd='/etc/dvmrpd.conf'
                if [ -f $dvmrpd ]; then
                        cp /etc/dvmrpd.conf /var/nsh/backup/pre-nsh-config/
                        cp /etc/dvmrpd.conf /var/run/dvmrpd.conf.0
                        chown root /var/run/dvmrpd.conf.0
                        chgrp wheel /var/run/dvmrpd.conf.0
                        chmod 660 /var/run/dvmrpd.conf.0
                else
                        echo etc-dvmrpd does not exist, not importing!
                fi

                sasync='/etc/sasyncd.conf'
                if [ -f $sasync ]; then
                        cp /etc/sasyncd.conf /var/nsh/backup/pre-nsh-config/
                        cp /etc/sasyncd.conf /var/run/sasyncd.conf.0
                        chown root /var/run/sasyncd.conf.0
                        chgrp wheel /var/run/sasyncd.conf.0
                        chmod 660 /var/run/sasyncd.conf.0
                else
                        echo etc-sasyncd does not exist, not importing!
                fi

                #nshd's users, and the group nshadmin
                groupinfo -e nshadmin || groupadd nshadmin
                for u in _nshshow _nshfront _nshconf _nsharc _nshcheck; do
                        userinfo -e $u || useradd -L daemon -d /var/empty \
                            -s /sbin/nologin $u
                done
                #start nshd without -b, so that it applies no configuration
                /usr/local/sbin/nshd
                i=0
                while [ ! -S /var/run/nshd.sock ] && [ $i -lt 10 ]; do
                        sleep 1
                        i=$((i + 1))
                done
                #save the running configuration as /var/db/nsh/nshrc
                echo commit | /usr/local/bin/nsh
                #stop nshd's parent; its other processes end with it
                pkill -xf /usr/local/sbin/nshd
                if [ ! -f /var/db/nsh/nshrc ]; then
                        echo nsh could not save the running configuration!
                        exit 1
                fi
                #rc starts nshd at each boot, and nshd then applies the
                #saved configuration
                cp ../../rc.d/nshd /etc/rc.d/nshd
                chmod 555 /etc/rc.d/nshd
                rcctl enable nshd
                echo Restart the system, and check that nsh shows the
                echo configuration you expect.
        else
                exit
        fi
fi
