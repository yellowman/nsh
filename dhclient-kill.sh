#!/bin/sh
# $nsh: dhclient-kill.sh,v 1.1 2005/08/30 01:43:54 chris Exp $
#
# This script is called by NSH when a user enters 'no ip dhcp' in 
# interface configuration mode.
#

rm -f /var/db/dhclient.leases.$1
pkill dhclient $1

sync
