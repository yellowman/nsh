#!/bin/sh
# $nsh: save-ro.sh,v 1.2 2003/02/18 09:29:46 chris Exp $
#
# This script is called by NSH when it wants to permanently save the
# configuration to disk/flash.  This script can be modified by the user
# to do more if necessary.
#

if [ ! -f "$1" ]; then
  echo save.sh: not found: $1
  exit
fi

mount -o rw,noatime /dev/wd0a /
cp $1 /etc/nshrc
#cp /var/run/pf.conf /etc/pf.conf
mount -o ro /dev/wd0a /
