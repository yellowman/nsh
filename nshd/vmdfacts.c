/*
 * Copyright (c) 2026 Chris Cappuccio <chris@nmedia.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * show vmd status: what vmd(8) says of each VM, asked on its control
 * socket by a child of nshd's system that is the session's user, so the
 * socket's permissions decide whether the user may ask. The child sends
 * system nsh's own records, each unit after its length, and system
 * passes them on (systemproc.c).
 *
 * The messages are vmd's, from proc.h and vmd.h in OpenBSD's source.
 * vmd keeps them to itself, and they change with it, so the child takes
 * only the types it knows, each of the length it knows, and ends the
 * show at any other, saying so.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <grp.h>
#include <imsg.h>
#include <login_cap.h>
#include <poll.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "externs.h"
#include "facts.h"
#include "showfacts.h"

#ifndef VMD_SOCKET
#define VMD_SOCKET	"/var/run/vmd.sock"	/* SOCKET_NAME */
#endif
#define VMD_WAIT	5000	/* ms vmd has to send each message */

/* vmd's messages, and what they carry */
#define VMD_FAIL		2	/* IMSG_CTL_FAIL: an errno */
#define VMD_INFO_REQUEST	19	/* IMSG_VMDOP_GET_INFO_VM_REQUEST */
#define VMD_INFO_DATA		20	/* a struct vmd_info */
#define VMD_INFO_END		21	/* 0, or why running VMs are missing */
#define VMD_VCPUS		64	/* VMM_MAX_VCPUS_PER_VM */
#define VMD_TTYNAME		16	/* VM_TTYNAME_MAX */
#define VMD_RUNNING		0x01	/* VM_STATE_* */
#define VMD_DISABLED		0x02
#define VMD_SHUTDOWN		0x04
#define VMD_PAUSED		0x10
#define VMD_WAITING		0x20

/* a VM, as vmd says it: struct vmop_info_result */
struct vmd_info {
	size_t		 memory;
	size_t		 used;
	size_t		 ncpus;
	uint8_t		 vcpu_state[VMD_VCPUS];
	pid_t		 pid;
	uint32_t	 id;
	char		 name[VM_NAMELEN];
	char		 tty[VMD_TTYNAME];
	uid_t		 uid;
	int64_t		 gid;
	unsigned int	 state;
};

/* a unit, to system, after its length; the child ends if it cannot */
static void
vmd_unit(void *arg, const void *buf, size_t len)
{
	uint8_t		 n[2] = { len >> 8, len & 0xff };

	if (write(STDOUT_FILENO, n, sizeof(n)) != sizeof(n) ||
	    write(STDOUT_FILENO, buf, len) != (ssize_t)len)
		_exit(1);
}

/* a VM's state, as vmctl names it: of the bits set, the first here */
static int
vmd_state(unsigned int mask)
{
	if (mask & VMD_PAUSED)
		return (VMS_PAUSED);
	if (mask & VMD_WAITING)
		return (VMS_WAITING);
	if (mask & VMD_SHUTDOWN)
		return (VMS_STOPPING);
	if (mask & VMD_RUNNING)
		return (VMS_RUNNING);
	if (mask == 0 || (mask & VMD_DISABLED))
		return (VMS_STOPPED);
	return (VMS_UNKNOWN);
}

/* vi, as a record: a pid and memory used only if it runs, and no tty */
static int
vmd_record(struct facts_out *o, const struct vmd_info *vi)
{
	struct facts_value	 v[VM_NFIELDS];
	struct passwd		*pw;
	struct group		*gr;

	memset(v, 0, sizeof(v));
	facts_u64(&v[VM_ID], vi->id);
	facts_string(&v[VM_NAME], vi->name);
	facts_u64(&v[VM_STATE], vmd_state(vi->state));
	if (vi->pid != 0 && vi->id != 0) {
		facts_u64(&v[VM_PID], vi->pid);
		facts_u64(&v[VM_USED], vi->used);
	}
	facts_u64(&v[VM_VCPUS], vi->ncpus);
	facts_u64(&v[VM_MEMORY], vi->memory);
	facts_u64(&v[VM_UID], vi->uid);
	if ((pw = getpwuid(vi->uid)) != NULL)
		facts_string(&v[VM_OWNER], pw->pw_name);
	/* -1 for none */
	if (vi->gid >= 0 && vi->gid <= UINT32_MAX) {
		facts_u64(&v[VM_GID], vi->gid);
		if ((gr = getgrgid(vi->gid)) != NULL)
			facts_string(&v[VM_GROUP], gr->gr_name);
	}
	return (facts_record(o, &kind_vm, v));
}

/* is vi the VM vm names: by its id if vm is a number, else its name */
static int
vmd_named(const struct vmd_info *vi, const char *vm)
{
	const char	*errstr;
	uint32_t	 id;

	id = strtonum(vm, 1, UINT32_MAX, &errstr);
	if (errstr == NULL)
		return (vi->id == id);
	return (strcmp(vi->name, vm) == 0);
}

/*
 * As pw's user, a connection to vmd's control socket, with only stdio
 * and getpw left; -1, after saying why, if there is none
 */
static int
vmd_open(struct facts_out *o, struct passwd *pw)
{
	struct sockaddr_un	 sun;
	int			 fd;

	if (setusercontext(NULL, pw, pw->pw_uid,
	    LOGIN_SETGROUP | LOGIN_SETUSER) == -1) {
		facts_message(o, "%% nshd: cannot become %s\n", pw->pw_name);
		return (-1);
	}
	if (pledge("stdio unix getpw", NULL) == -1 ||
	    (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		facts_message(o, "%% vmd: %s\n", strerror(errno));
		return (-1);
	}
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, VMD_SOCKET, sizeof(sun.sun_path));
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		if (errno == EACCES || errno == EPERM)
			facts_message(o, "%% vmd: %s may not use its control "
			    "socket\n", pw->pw_name);
		else if (errno == ENOENT || errno == ECONNREFUSED)
			facts_message(o, "%% vmd is not running\n");
		else
			facts_message(o, "%% vmd: %s\n", strerror(errno));
		return (-1);
	}
	if (pledge("stdio getpw", NULL) == -1) {
		facts_message(o, "%% vmd: %s\n", strerror(errno));
		return (-1);
	}
	return (fd);
}

/* the next message from vmd, into imsg: 0, or -1 after saying why not */
static int
vmd_next(struct facts_out *o, int fd, struct imsgbuf *ib, struct imsg *imsg)
{
	struct pollfd	 pfd;
	ssize_t		 n;

	while ((n = imsgbuf_get(ib, imsg)) == 0) {
		pfd.fd = fd;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, VMD_WAIT) != 1 ||
		    (n = imsgbuf_read(ib)) == 0 ||
		    (n == -1 && errno != ERANGE && errno != EBADMSG)) {
			facts_message(o, "%% vmd did not answer\n");
			return (-1);
		}
		/* a message whose header imsg refuses */
		if (n == -1)
			break;
	}
	if (n == 1)
		return (0);
	facts_message(o, "%% vmd sent an answer nsh cannot read\n");
	return (-1);
}

/*
 * vmd's answer, on fd: each VM, or the one vm names if vm is not NULL,
 * as a record. 0, or -1 after saying why the show ends
 */
static int
vmd_list(struct facts_out *o, int fd, const char *vm)
{
	struct imsgbuf		 ib;
	struct imsg		 imsg;
	struct vmd_info		 vi;
	int			 err, found = 0;

	if (imsgbuf_init(&ib, fd) == -1 ||
	    imsg_compose(&ib, VMD_INFO_REQUEST, 0, 0, -1, NULL, 0) == -1 ||
	    imsgbuf_flush(&ib) == -1) {
		facts_message(o, "%% vmd: %s\n", strerror(errno));
		return (-1);
	}
	for (;;) {
		if (vmd_next(o, fd, &ib, &imsg) == -1)
			return (-1);
		switch (imsg_get_type(&imsg)) {
		case VMD_INFO_DATA:
			if (imsg_get_data(&imsg, &vi, sizeof(vi)) == -1 ||
			    memchr(vi.name, '\0', sizeof(vi.name)) == NULL)
				goto unread;
			if (vm != NULL && !vmd_named(&vi, vm))
				break;
			found = 1;
			if (vmd_record(o, &vi) == -1) {
				imsg_free(&imsg);
				facts_message(o, "%% nshd: VM %s cannot be "
				    "sent\n", vi.name);
				return (-1);
			}
			break;
		case VMD_INFO_END:
			if (imsg_get_data(&imsg, &err, sizeof(err)) == -1)
				goto unread;
			imsg_free(&imsg);
			if (err != 0) {
				facts_message(o, "%% vmd did not list every "
				    "running VM: %s\n", strerror(err));
				return (-1);
			}
			if (vm != NULL && !found) {
				facts_message(o, "%% vmd has no VM %s\n", vm);
				return (-1);
			}
			return (0);
		case VMD_FAIL:
			if (imsg_get_data(&imsg, &err, sizeof(err)) == -1)
				goto unread;
			facts_message(o, "%% vmd refused: %s\n", strerror(err));
			imsg_free(&imsg);
			return (-1);
		default:
			goto unread;
		}
		imsg_free(&imsg);
	}
 unread:
	imsg_free(&imsg);
	facts_message(o, "%% vmd sent an answer nsh cannot read\n");
	return (-1);
}

/*
 * In system's child for show vmd status: as pw's user, each VM vmd has,
 * or the one vm names if vm is not NULL, to system. The child's exit
 * status: 0, or 1 after saying why the show ends
 */
int
vmd_facts(struct passwd *pw, const char *vm)
{
	struct facts_out	 o;
	int			 fd;

	facts_out_init(&o, vmd_unit, NULL);
	if ((fd = vmd_open(&o, pw)) == -1 || vmd_list(&o, fd, vm) == -1)
		return (1);
	return (0);
}
