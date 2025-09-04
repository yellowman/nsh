#!/bin/sh -
#needs to be run as root 
#comments and feedback welcome tom [dot] smyth [at] wirelessconnect [dot] eu
#This script is an example setup which  
# 1. patches the system
# 2. installs packages that can be useful for a router / firewall
# 3. downloads the latest master nsh from github 
# 4. sets up mfs for /var/log,  /tmp ,  /var/run and /dev
# 5. runs the nsh integration script so that the OpenBSD box is
#    fully managed using nsh.
# 6. turns off sndiod as it is not used on a router typically
# 7. sets nsh as the default shell for the user "fireman" Change to suit your needs
 

dflt='No'

#check if user is root
if [ $(id -u) != 0 ];
then
    echo "Must be run as root"
    exit
else
    #ask user do they want to continue
    #default is No
    echo "This script is to help improve reliability of OpenBSD Network"
    echo "Appliances especially regarding file systems in situations"
	echo "where the appliance is running with impaired power reliability" 
    echo "The import script will require user verification"
    echo "This script is designed to assist a user with integrating nsh" 
	echo "on OpenBSD."
	echo "Please read and review this script to understand the changes"
	echo "the script would make to your system before you continue!"
    read input?"Do you want to continue? (Yes/No) [${dflt}] "
    if [ -z "${input}" ]; then input="${dflt}"; fi
    if [ "${input}" = 'Yes' ] || [ "${input}" = 'yes' ];
        then
			#patch system
			syspatch
			#install useful packages for a router / firewall feedback welcome
			#on packages that are useful to include
			#update existing / installed packages
			pkg_add -u	
			#network shell
			pkg_add nsh-1.2.3-static
			#install game of trees git software 
			pkg_add got			
			#install git 
			pkg_add git
			#install active network diagnostic tools 				pkg_add mtr-0.95v0	
			pkg_add tcptraceroute
			pkg_add fping
			pkg_add hping
			pkg_add arping 
			pkg_add dhcping
			pkg_add flow-tools
			pkg_add tcpstat
			pkg_add arp-scan
			#install passive performance monitoring tools
			pkg_add nload
			pkg_add iftop
			pkg_add pftop
			#install active network fuzzing scanning tools
			pkg_add nmap
			pkg_add scapy
			#install performance benchmarking tools 				
			pkg_add iperf3
			pkg_add speedtest-cli
			#install optional network protocol daemons	
			pkg_add ladvd
			pkg_add lldpd-1.0.19
			pkg_add openvpn-2.6.14
			#install firmware or bios update software	
			#pkg_add flashrom
			#uncomment  the following netflow analysers for now 
			#pkg_add nfsen
			#pkg_add nfdump
			#pkg_add nfprofile
			#disable sound subsystem as not required for a router
			rcctl disable sndiod
			rcctl stop sndiod
			#disable debug after panic	
			echo ddb.panic=0 >> /etc/sysctl.conf
			#install latest version of nsh from github
			cd /root
			git clone https://github.com/yellowman/nsh/
			cd /root/nsh
			make static
			make install 
			# No longer required copy example scripts	to standard openbsd example directory
			#	 cd /root/nsh/scripts/
			#	 cp -R * /usr/local/share/examples/nsh/
			#update the locate database after installation of packages
			sh /etc/weekly
			#make location for storing persisting data on mfs filesystems
			mkdir -p /persist-fs/dev
			mkdir -p /persist-fs/tmp
			mkdir -p /persist-fs/var/run
			mkdir -p /persist-fs/var/log
			cp -Rp /var/run/* /persist-fs/var/run
			cp -Rp /var/log/* /persist-fs/var/log
			cp -Rp /tmp/* /persist-fs/tmp/
			#create new dev 
			cp -Rp /dev/MAKEDEV /persist-fs/dev/
			cd /persist-fs/dev/
			/persist-fs/dev/MAKEDEV all
			#review the next line for security set sticky bit and world writable
			chmod 1777 /persist-fs/tmp
			umount /tmp
			chmod 1755 /tmp
			cd
			#fstab filesystem risk reduction reducing wear and probability of disk wear
			cd /etc
			cp /etc/fstab /root/fstab-backup
			#remove default tmp reference
			sed -i '/\/tmp/d' /etc/fstab
			#remove swap file 
			sed -i '/swap/d' /etc/fstab
			#configure all ffs systems with sync and noatime options  
			sed -i 's/ffs rw 1 1/ffs rw,sync,noatime 1 1/' /etc/fstab
			sed -i 's/ffs rw,wxallowed,nodev 1 2/ffs rw,wxallowed,nodev,sync,noatime 1 2/' /etc/fstab
			sed -i 's/ffs rw,nodev,nosuid 1 2/ffs rw,nodev,nosuid,sync,noatime 1 2/' /etc/fstab
			#mount as memory filesystems directories with regularly written / updated files
			echo swap \/tmp mfs rw,nosuid,noexec,nodev,\-s\=262144 0 0 >>/etc/fstab
			echo swap \/var\/log mfs rw,nosuid,noexec,nodev,\-s\=524288,\-P\=\/persist\-fs\/var\/log 0 0 >>/etc/fstab				echo swap \/var\/run mfs rw,nosuid,noexec,nodev,\-s\=262144,\-P=\/persist\-fs\/var\/run 0 0 >>/etc/fstab
			echo swap \/dev mfs rw,nosuid,noexec,\-P=\/persist\-fs\/dev,\-i\=2048,\-s\=32768 0 0 >>/etc/fstab
			#change default shell for user fireman 
			chsh -s /usr/local/bin/nsh fireman
			#call these next two commands to integrate NSHell with openBSD   
			cd /usr/local/share/examples/nsh/shell
			#call this to integrate NSHell with openBSD 
			sh  rc.local-nsh-openbsd-integrate.sh  				
        else
            exit
        fi
		