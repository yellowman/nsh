#!/bin/sh

# capture keys & settings from a flashrd system

# /etc/isakmpd
# /etc/iked
# /etc/ssh

# /etc/rc.local
# /etc/rc.conf.local
# /etc/adduser.conf - from common
# /etc/shells - from common
# /etc/sudoers - from common

# /usr/local

hostname=`/bin/hostname`
cd /

/bin/tar zcf "/flash/${hostname}.tgz" \
	etc/isakmpd etc/iked etc/ssh \
	etc/rc.local etc/rc.conf.local \
	usr/local

skipList="boot bsd bsd.mp etc new old openbsd.vnd var.tar ${hostname}.tgz ${hostname}_flash.tgz"
FLASH_SAVE_DIRS=" "
for oneDir in `/bin/ls /flash`; do
	
	echo "$skipList" | /usr/bin/grep $oneDir > /dev/null
	if [[ $? -ne 0 ]]; then
		echo $oneDir
		FLASH_SAVE_DIRS="${FLASH_SAVE_DIRS} ${oneDir}"
	fi
	
done

cd /flash
# $FLASH_SAVE_DIRS deliberately not quoted! 
/bin/tar zcf "/flash/${hostname}_flash.tgz" ${FLASH_SAVE_DIRS}


