#!/bin/sh -

#This Script integrates nsh with OpenBSD by *moving*
#config files for daemons from \/etc\/ to \/var\/run\/
#the moved config files are also saved to \/var\/nsh\/backup\/pre-nsh-config\/
#this script assumes it is importing a basic single rdomain setup and will
#attempt to import daemons that are supported by nsh.
#only run this script if you intend to manage the system via nsh.


dflt='No'

#check if user is root
if [ $(id -u) != 0 ];
then
	echo "Must be run as root"
	exit
else
	#ask user do they want to continue
	#default is No
 	echo "This script takes a more invasive approach and is intended for 
  	echo "Administrators who inend to permanently move to nsh to manage the 
   	echo "configuration on the system"
        echo "If you have an unusual config, e.g. multiple routing domains"
	echo "If you have an unusual config, it is not recommended to run" 
 	echo "Without carefully reviewing the the script and"
	read input?"Do you want to continue? (Yes/No) [${dflt}] "

	if [ -z "${input}" ]; then input="${dflt}"; fi
	if [ "${input}" = 'Yes' ] || [ "${input}" = 'yes' ];
	then
		test -f /var/nsh/backup/pre-nsh-config && echo pre-nsh-config exists already && exit
		test -f /etc/nshrc && echo etc-nshrc exists already && exit
		 
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
			mv /etc/pf.conf /var/run/pf.conf.0
			chown root /var/run/pf.conf.0
			chgrp wheel /var/run/pf.conf.0
			chmod 660 /var/run/pf.conf.0
		else
			echo etc-pf does not exist, not importing!
		fi

		ipsec='/etc/ipsec.conf'
		if [ -f $ipsec ]; then
			cp /etc/ipsec.conf /var/nsh/backup/pre-nsh-config/
			mv /etc/ipsec.conf /var/run/ipsec.conf.0
			chown root /var/run/ipsec.conf.0
			chgrp wheel /var/run/ipsec.conf.0
			chmod 660 /var/run/ipsec.conf.0
		else
			echo etc-ipsec does not exist, not importing!
		fi
		 
		bgpd='/etc/bgpd.conf'
		if [ -f $bgpd ]; then
			cp /etc/bgpd.conf /var/nsh/backup/pre-nsh-config/
			mv /etc/bgpd.conf /var/run/bgpd.conf.0
			chown root /var/run/bgpd.conf.0
			chgrp wheel /var/run/bgpd.conf.0
			chmod 660 /var/run/bgpd.conf.0
		else
			echo etc-bgpd does not exist, not importing!
		fi
		 
		ospfd='/etc/ospfd.conf'
		if [ -f $ospfd ]; then
			cp /etc/ospfd.conf /var/nsh/backup/pre-nsh-config/
			mv /etc/ospfd.conf /var/run/ospfd.conf.0
			chown root /var/run/ospfd.conf.0
			chgrp wheel /var/run/ospfd.conf.0
			chmod 660 /var/run/ospfd.conf.0
		else
			echo etc-ospfd does not exist, not importing!
		fi
		 
		 
		ospf6d='/etc/ospf6d.conf'
		if [ -f $ospf6d ]; then
			cp /etc/ospf6d.conf /var/nsh/backup/pre-nsh-config/
			mv /etc/ospf6d.conf /var/run/ospf6d.conf.0
			chown root /var/run/ospf6d.conf.0
			chgrp wheel /var/run/ospf6d.conf.0
			chmod 660 /var/run/ospf6d.conf.0
		else
			echo etc-ospf6d does not exist, not importing!
			
		fi
		dhcpd='/etc/dhcpd.conf'
		if [ -f $dhcpd ]; then
			cp /etc/dhcpd.conf /var/nsh/backup/pre-nsh-config/
			mv /etc/dhcpd.conf /var/run/dhcpd.conf.0
			chown root /var/run/dhcpd.conf.0
			chgrp wheel /var/run/dhcpd.conf.0
			chmod 660 /var/run/dhcpd.conf.0
		else
			echo etc-dhcpd does not exist, not importing!
		fi
		
		ntpd='/etc/ntpd.conf'
		if [ -f $ntpd ]; then
			cp /etc/ntpd.conf /var/nsh/backup/pre-nsh-config/
			mv /etc/ntpd.conf /var/run/ntpd.conf.0
			chown root /var/run/ntpd.conf.0
			chgrp wheel /var/run/ntpd.conf.0
			chmod 660 /var/run/ntpd.conf.0
		else
			echo etc-ntpd does not exist, not importing!
		fi
		 
		sshd_config='/etc/ssh/sshd_config'
		if [ -f $sshd_config ]; then
			cp /etc/ssh/sshd_config /var/nsh/backup/pre-nsh-config/
			mv /etc/ssh/sshd_config /var/run/sshd.conf.0
			chown root /var/run/sshd.conf.0
			chgrp wheel /var/run/sshd.conf.0
			chmod 660 /var/run/sshd.conf.0
		else
			echo etc-ssh_config does not exist, not importing!
		fi

		eigrpd='/etc/eigrpd.conf'
		if [ -f $eigrpd ]; then
			cp /etc/eigrpd.conf /var/nsh/backup/pre-nsh-config/
			mv /etc/eigrpd.conf /var/run/eigrpd.conf.0
			chown root /var/run/eigrpd.conf.0
			chgrp wheel /var/run/eigrpd.conf.0
			chmod 660 /var/run/eigrpd.conf.0
		else
			echo etc-eigrpd does not exist, not importing!
		fi

		relayd='/etc/relayd.conf'
		if [ -f $relayd ]; then
			cp /etc/relayd.conf /var/nsh/backup/pre-nsh-config/
			mv /etc/relayd.conf /var/run/relayd.conf.0
			chown root /var/run/relayd.conf.0
			chgrp wheel /var/run/relayd.conf.0
			chmod 660 /var/run/relayd.conf.0
		else
			echo etc-relayd does not exist, not importing!
		fi

		ripd='/etc/ripd.conf'
		if [ -f $ripd ]; then
			cp /etc/ripd.conf /var/nsh/backup/pre-nsh-config/
			mv /etc/ripd.conf /var/run/ripd.conf.0
			chown root /var/run/ripd.conf.0
			chgrp wheel /var/run/ripd.conf.0
			chmod 660 /var/run/ripd.conf.0
		else
			echo etc-ripd does not exist, not importing!
		fi
		 
		ldpd='/etc/ldpd.conf'
		if [ -f $ldpd ]; then
			cp /etc/ldpd.conf /var/nsh/backup/pre-nsh-config/
			mv /etc/ldpd.conf /var/run/ldpd.conf.0
			chown root /var/run/ldpd.conf.0
			chgrp wheel /var/run/ldpd.conf.0
			chmod 660 /var/run/ldpd.conf.0
		else
			echo etc-ldpd does not exist, not importing!
		fi
		 
		iked='/etc/iked.conf'
		if [ -f $iked ]; then
			cp /etc/iked.conf /var/nsh/backup/pre-nsh-config/
			mv /etc/iked.conf /var/run/iked.conf.0
			chown root /var/run/iked.conf.0
			chgrp wheel /var/run/iked.conf.0
			chmod 660 /var/run/iked.conf.0
		else
			echo etc-iked does not exist, not importing!
		fi

		snmpd='/etc/snmpd.conf'
		if [ -f $snmpd ]; then
			cp /etc/snmpd.conf /var/nsh/backup/pre-nsh-config/
			mv /etc/snmpd.conf /var/run/snmpd.conf.0
			chown root /var/run/snmpd.conf.0
			chgrp wheel /var/run/snmpd.conf.0
			chmod 660 /var/run/snmpd.conf.0
		else
			echo etc-snmpd does not exist, not importing!
		fi
		 
		ldapd='/etc/ldapd.conf'
		if [ -f $ldapd ]; then
			cp /etc/ldapd.conf /var/nsh/backup/pre-nsh-config/
			mv /etc/ldapd.conf /var/run/ldapd.conf.0
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
			mv /etc/motd /var/run/motd.0
			sed -i 's/Welcome to OpenBSD/OpenBSD/g' /var/run/motd.0
			ln -s /var/run/motd.0 /etc/motd
			chown root /var/run/motd.0
			chgrp wheel /var/run/motd.0
			chmod 660 /var/run/motd.0
		else 
			echo etc-motd does not exist, not importing!
		fi
		
		smtpd='/etc/mail/smtpd.conf'
		if [ -f $smtpd ]; then
			cp /etc/mail/smtpd.conf /var/nsh/backup/pre-nsh-config/
			mv /etc/mail/smtpd.conf /var/run/smtpd.conf.0
			chown root /var/run/smtpd.conf.0
			chgrp wheel /var/run/smtpd.conf.0
			chmod 660 /var/run/smtpd.conf.0
		else 
			echo etc-smtpd does not exist, not importing!
		fi
		
		dvmrpd='/etc/dvmrpd.conf'
		if [ -f $dvmrpd ]; then
			cp /etc/dvmrpd.conf /var/nsh/backup/pre-nsh-config/
			mv /etc/dvmrpd.conf /var/run/dvmrpd.conf.0
			chown root /var/run/dvmrpd.conf.0
			chgrp wheel /var/run/dvmrpd.conf.0
			chmod 660 /var/run/dvmrpd.conf.0
		else 
			echo etc-dvmrpd does not exist, not importing!
		fi
		
		sasync='/etc/sasync.conf'
		if [ -f $sasync ]; then
			cp /etc/sasync.conf /var/nsh/backup/pre-nsh-config/
			mv /etc/sasync.conf /var/run/sasync.conf.0
			chown root /var/run/sasync.conf.0
			chgrp wheel /var/run/sasync.conf.0
			chmod 660 /var/run/sasync.conf.0
		else 
			echo etc-sasyncd does not exist, not importing!
		fi
		
		#setup and secure nshlog 
		touch /var/log/nsh.log
		chown root /var/log/nsh.log
		chgrp wheel /var/log/nsh.log
		chmod 660 /var/log/nsh.log
		#import running Openbsd kernel configuration
		/usr/local/bin/nsh -c ../nshrc/write-config.nshrc
		#secure nshrc config file 
		chmod 660 /etc/nshrc
		#Remove any networking config from /etc/ that conflicts with nsh
		mv /etc/hostname.* /var/nsh/backup/pre-nsh-config/
		mv /etc/mygate /var/nsh/backup/pre-nsh-config/
		#can we import rc.conf.local to nsh config
		mv /etc/rc.conf.local /var/nsh/backup/pre-nsh-config/
		cp nsh.rc /etc/rc.d/nsh
		chmod 555 /etc/rc.d/nsh
		#enable nsh 
		rcctl enable nsh
		#disable services now managed by nsh 
		rcctl disable ntpd
		rcctl disable smtpd
		rcctl disable sshd
		echo reboot device for nsh configuration to take effect
		/usr/local/bin/nsh -c ../nshrc/enable-sshd.nshrc
  		/usr/local/bin/nsh -c ../nshrc/write-config.nshrc
	else
		exit
	fi
fi
