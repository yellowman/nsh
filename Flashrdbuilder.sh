#!/bin/sh

#
# Flashrdbuilder.sh
#
# Tool for maintaining a set of hosts built with flashrd
#
# Works a little like radmind, but can append to files as well as making copies
# Knows about common vs host-specific files. Keeps things like host keys across 
# rebuilds
#
# Requires a hacked version of cfgflashrd that accepts additional params 
# plus the root password on stdin
#
# 2012-07-06 Paul Suh
#
# Works with flashrd-1.1a
#


printUsage()
{
 cat <<EOF
Usage: ./Flashrdbuilder.sh [options] "flashimg.arch-XXXXXXXX"

Options:
    -r | -rdroot "filename" rdrootfs image (needed only to change ramdisk)
    -e "dir"                directory where elfrdsetroot.c is located (only with -r)
    -c | -com0 "speed"      set com0 as console at speed "speed"
    -m | -mp                set bsd.mp as primary kernel
    -s | -sp                set bsd.sp as primary kernel
    -dns "dns server"       list of DNS servers, separated by spaces
    -ntp "ntp servers"      list of NTP servers, separated by spaces
    -hostname "target hostname"     fully qualified name of target host (required) 
    -basedir "/path/to/basedir"     path to directory with common and host-specific directories
    -t | -tz "tzfile"       set timezone using a timezone file from
                            /usr/share/zoneinfo

EOF
}

findFirstFreeVnd() 
{
	FIND_FIRST_FREE_VND_RETURN=`/sbin/vnconfig -l | /usr/bin/grep "not in use" | /usr/bin/head -1 | /usr/bin/cut -c 1-4`
	
	if [[ -z ${FIND_FIRST_FREE_VND_RETURN} ]]; then
		echo "No free vnd devices found"
		exit 1
	fi

}


# Appends text to files
# looks in the APPEND subdir
# $1 contains the current directory
# $2 contains the target directory
appendOnDir()
{
	if [[ ! -d "${1}" ]]; then
		return
	fi
	ORIG_PATH=`pwd`
	cd "${1}"
	echo "In directory: " `/bin/pwd`
	FILE_LIST=`/usr/bin/find . -type f`
	
	for ONE_FILE in ${FILE_LIST}; do
	
		echo "appending: ${ONE_FILE} to ${2}/${ONE_FILE}"
	
		/bin/cat "${ONE_FILE}" >> "${2}/${ONE_FILE}"
		
	done
	
	cd "${ORIG_PATH}"
}


t2() {
 if [ -z "$1" ]; then
  usage
  exit 1
 fi
}


# all of these variables should be passed in to cfgflashrd
while :
do
 case $1 in
  -\?)		usage; exit 0;;
  -r|-rdroot)	t2 "$2"; rdfs="$2"; shift 2;;
  -c|-com0)	    t2 "$2"; com0="$2"; shift 2;;
  -m|-mp)	    t2 "$2"; kernel="bsdmp"; shift;;
  -s|-sp)	    t2 "$2"; kernel="bsdsp"; shift;;
  -t|-tz)	    t2 "$2"; tzfile="$2"; shift 2;;
  -dns)         t2 "$2"; dnsservers="$2"; shift 2;;
  -ntp)         t2 "$2"; ntpservers="$2"; shift 2;;
  -hostname)    t2 "$2"; hostname="$2"; shift 2;;
  -basedir)     t2 "$2"; basedir="$2"; shift 2;;
  -e)		    t2 "$2"; elfrdsetrootdir="$2"; shift 2;;

  --)		shift; break;;
  -*)		printUsage; exit 1;;
  *)		break;;
 esac
done

# last arg left should be flashrd image
image="$1"

echo "rfds=$rdfs"
echo "com0=$com0"
echo "kernel=$kernel"
echo "tzfile=$tzfile"
echo "dnsservers=$dnsservers"
echo "ntpservers=$ntpservers"
echo "hostname=$hostname"
echo "basedir=$basedir"
echo "elfrdsetrootdir=$elfrdsetrootdir"

echo "Flashrdbuilder 1.1 paul.suh@ps-enable.com"
echo "Starting build process..."

# don't shift, set target as image
IMAGE_NAME_DATE=`/bin/date +%Y%m%d`
IMAGE_NAME="${image}"

echo "Build using image ${IMAGE_NAME}"

# determine absolute path to this script

ORIG_PATH="$(pwd)"
cd "$(dirname $0)"
BIN_PATH="$(pwd)"
cd "${ORIG_PATH}"

# copy the disk image to a destination location
IMAGE_NAME_DATETIME=`/bin/date +%Y%m%d%H%M`
HOST_DIR="${basedir}/${hostname}-${IMAGE_NAME_DATETIME}"
echo "Copying disk image to ${HOST_DIR}"
/bin/mkdir "${HOST_DIR}"
/bin/cp "${image}" "${HOST_DIR}"

image="${HOST_DIR}/${image}"

echo "Executing cfgflashrd..."

# cfgflashrd will read in password
# all other params should be already set
. ./cfgflashrd 

# mount the main disk and the vnode disks
# vnd0a - /root
# vnd0d - /bin
# vnd0e - /etc
# vnd0f - /sbin
# vnd0g - /usr

unset TMPDIR
BASE_MOUNT_DIR="$(/usr/bin/mktemp -p /mnt -d flashrdbase.XXXXXX)"

findFirstFreeVnd
IMAGE_VND=${FIND_FIRST_FREE_VND_RETURN}

/sbin/vnconfig ${IMAGE_VND} "${HOST_DIR}/${IMAGE_NAME}"
/sbin/mount /dev/${IMAGE_VND}a "${BASE_MOUNT_DIR}"
	
echo "Mounted image ${HOST_DIR}/${IMAGE_NAME} for customization"

findFirstFreeVnd
INSIDE_IMAGE_VND=${FIND_FIRST_FREE_VND_RETURN}

/sbin/vnconfig ${INSIDE_IMAGE_VND} "${BASE_MOUNT_DIR}"/openbsd.vnd

HOME_MOUNT_DIR="$(/usr/bin/mktemp -p /mnt -d flashrdhome.XXXXXX)"
/sbin/mount /dev/${INSIDE_IMAGE_VND}a "${HOME_MOUNT_DIR}"

BIN_MOUNT_DIR="$(/usr/bin/mktemp -p /mnt -d flashrdbin.XXXXXX)"
/sbin/mount /dev/${INSIDE_IMAGE_VND}d "${BIN_MOUNT_DIR}"

ETC_MOUNT_DIR="$(/usr/bin/mktemp -p /mnt -d flashrdetc.XXXXXX)"
/sbin/mount /dev/${INSIDE_IMAGE_VND}e "${ETC_MOUNT_DIR}"

SBIN_MOUNT_DIR="$(/usr/bin/mktemp -p /mnt -d flashrdsbin.XXXXXX)"
/sbin/mount /dev/${INSIDE_IMAGE_VND}f "${SBIN_MOUNT_DIR}"

USR_MOUNT_DIR="$(/usr/bin/mktemp -p /mnt -d flashrdusr.XXXXXX)"
/sbin/mount /dev/${INSIDE_IMAGE_VND}g "${USR_MOUNT_DIR}"

echo "Mounted all inner file systems"

# copy over the common elements 

echo "Copying over common elements..."
echo "   /flash..."
/bin/cp -Rp "${basedir}"/common/flash/* "${BASE_MOUNT_DIR}"/
echo "   /bin..."
/bin/cp -Rp "${basedir}"/common/bin/* "${BIN_MOUNT_DIR}"/
echo "   /etc..."
/bin/cp -Rp "${basedir}"/common/etc/* "${ETC_MOUNT_DIR}"/
echo "   /sbin..."
/bin/cp -Rp "${basedir}"/common/sbin/* "${SBIN_MOUNT_DIR}"/
echo "   /usr..."
/bin/cp -Rp "${basedir}"/common/usr/* "${USR_MOUNT_DIR}"/

# append common elements
echo "Appending common /etc elements..."
appendOnDir "${basedir}"/common/etc-APPEND "${ETC_MOUNT_DIR}"


# copy over the host-specific elements
echo "Copying over host-specific elements..."
echo "   /flash..."
/bin/cp -Rp "${basedir}"/host-specific/"${hostname}"/flash/* "${BASE_MOUNT_DIR}"/
echo "   /bin..."
/bin/cp -Rp "${basedir}"/host-specific/"${hostname}"/bin/* "${BIN_MOUNT_DIR}"/
echo "   /etc..."
/bin/cp -Rp "${basedir}"/host-specific/"${hostname}"/etc/* "${ETC_MOUNT_DIR}"/
echo "   /sbin..."
/bin/cp -Rp "${basedir}"/host-specific/"${hostname}"/sbin/* "${SBIN_MOUNT_DIR}"/
echo "   /usr..."
/bin/cp -Rp "${basedir}"/host-specific/"${hostname}"/usr/* "${USR_MOUNT_DIR}"/

# append common elements
echo "Appending host-specific /etc elements..."
appendOnDir "${basedir}"/host-specific/"${hostname}"/etc-APPEND "${ETC_MOUNT_DIR}"


# rebuild password databases for newly created users from appends
echo "Rebuilding password databases for new users in appended files..."
/usr/sbin/pwd_mkdb -d "${ETC_MOUNT_DIR}" "${ETC_MOUNT_DIR}"/master.passwd

# clean up
# unmount vnddirs
echo "Cleanup: unmounting inner file systems"
/sbin/umount "${HOME_MOUNT_DIR}"
/sbin/umount "${BIN_MOUNT_DIR}"
/sbin/umount "${ETC_MOUNT_DIR}"
/sbin/umount "${SBIN_MOUNT_DIR}"
/sbin/umount "${USR_MOUNT_DIR}"

# delete vnconfig
/sbin/vnconfig -u ${INSIDE_IMAGE_VND}

#
# at this point, copy out the interior files to make upgrades easy
#
echo "Copying out inner files"
/bin/cp "${BASE_MOUNT_DIR}/bsd" "${HOST_DIR}/bsd"
/bin/cp "${BASE_MOUNT_DIR}/openbsd.vnd" "${HOST_DIR}/openbsd.vnd"
/bin/cp "${BASE_MOUNT_DIR}/var.tar" "${HOST_DIR}/var.tar"

# unmount base flash drive
echo "Cleanup: unmounting outer file system"
/sbin/umount "${BASE_MOUNT_DIR}"

# unconfigure disk image vnd if necessary
# then copy disk image to named file
/sbin/vnconfig -u ${IMAGE_VND}

# delete temp dirs
echo "Cleanup: deleteing temp directories"
/bin/rmdir "${HOME_MOUNT_DIR}"
/bin/rmdir "${BIN_MOUNT_DIR}"
/bin/rmdir "${ETC_MOUNT_DIR}"
/bin/rmdir "${SBIN_MOUNT_DIR}"
/bin/rmdir "${USR_MOUNT_DIR}"
/bin/rmdir "${BASE_MOUNT_DIR}"

echo "flashrdbuilder completed"
