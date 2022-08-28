//===- hook.c - syscall hook ------------------------------------*- C++ -*-===//
//
/// \file
/// Syscall hook point handleer.
//
// Author:  zxh
// Date:    2022/08/21 17:01:18
//===----------------------------------------------------------------------===//

#include "hook.h"

#include <linux/kprobes.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/inet_sock.h>
#include <linux/sched.h>
#include <linux/string.h>

#define MAX_SYMBOL_LEN 64

void __kprobes recvfrom_post(struct kprobe *kp, struct pt_regs *regs, unsigned long flags)
{
	int addr_len;
	int fd;
	int err;
	struct sockaddr_storage addr;
	struct sockaddr_in *in;
	struct socket *sock;
	uint8_t *addrs;

	fd = (int)regs->di;
	if (regs->r9) {
		if (copy_from_user(&addr_len, (int *)regs->r9, sizeof(addr_len)))
			return;
		if (copy_from_user(&addr, (struct sockaddr *)regs->r8, addr_len))
			return;
		if (addr.ss_family == AF_INET) {
			in = (struct sockaddr_in *)&addr;
			addrs = (uint8_t *)&in->sin_addr.s_addr;
			pr_info("recvfrom -- Handle Post - Args - proc=%s pid=%d fd=%d remote_addr=%d.%d.%d.%d:%d\n",
				current->comm, current->pid, fd, addrs[0], addrs[1], addrs[2],
				addrs[3], ntohs(in->sin_port));
		}
	}

	sock = sockfd_lookup(fd, &err);
	if (!sock) {
		return;
	}

	if (kernel_getpeername(sock, (struct sockaddr *)&addr) < 0)
		goto out;

	if (addr.ss_family == AF_INET) {
		in = (struct sockaddr_in *)&addr;
		addrs = (uint8_t *)&in->sin_addr.s_addr;
		pr_info("recvfrom -- Handle Post - getpeername - proc=%s pid=%d fd=%d remote_addr=%d.%d.%d.%d:%d\n",
			current->comm, current->pid, fd, addrs[0], addrs[1], addrs[2], addrs[3],
			ntohs(in->sin_port));
	}

out:
	sockfd_put(sock);
}

static struct socket *sockfd_lookup_light(int fd, int *err, int *fput_needed)
{
	struct fd f = fdget(fd);
	struct socket *sock;

	*err = -EBADF;
	if (f.file) {
		sock = sock_from_file(f.file, err);
		if (likely(sock)) {
			*fput_needed = f.flags & FDPUT_FPUT;
			return sock;
		}
		fdput(f);
	}
	return NULL;
}

int __kprobes close_pre(struct kprobe *kp, struct pt_regs *regs)
{
	int fd;
	int err;
	int fput_needed;
	struct socket *sock;
	struct sockaddr_storage addr;
	struct sockaddr_in *remote_addr;
	struct sockaddr_in *local_addr;
	uint8_t *addrs;

	fd = (int)regs->si;
	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock) {
		return 0;
	}

	if (kernel_getpeername(sock, (struct sockaddr *)&addr) < 0)
		goto out;
	if (addr.ss_family == AF_INET) {
		remote_addr = (struct sockaddr_in *)&addr;
		addrs = (uint8_t *)&remote_addr->sin_addr.s_addr;
		pr_info("close -- Handle Pre - proc=%s pid=%d fd=%d remote_addr=%d.%d.%d.%d:%d\n",
			current->comm, current->pid, fd, addrs[0], addrs[1], addrs[2], addrs[3],
			ntohs(remote_addr->sin_port));
	}

	if (kernel_getsockname(sock, (struct sockaddr *)&addr) < 0)
		goto out;
	if (addr.ss_family == AF_INET) {
		local_addr = (struct sockaddr_in *)&addr;
		addrs = (uint8_t *)&local_addr->sin_addr.s_addr;
		pr_info("close -- Handle Pre - proc=%s pid=%d fd=%d local_addr=%d.%d.%d.%d:%d\n",
			current->comm, current->pid, fd, addrs[0], addrs[1], addrs[2], addrs[3],
			ntohs(local_addr->sin_port));
	}

out:
	if (fput_needed)
		sockfd_put(sock);
	return 0;
}

void __kprobes write_post(struct kprobe *kp, struct pt_regs *regs, unsigned long flags)
{
	int fd;

	fd = (int)regs->di;

	// TODO: remove echo test binary
	if (!strstr(current->comm, "echo"))
		return;

	pr_info("write -- Handle Post - pid=%d fd=%d\n", current->pid, fd);

	return;
}

#define EMBEDDED_NAME_MAX (PATH_MAX - offsetof(struct filename, iname))

void __kprobes open_post(struct kprobe *kp, struct pt_regs *regs, unsigned long flags)
{
	// int fd;
	int name_len;
	char filename[EMBEDDED_NAME_MAX];

	// TODO: remove a.out test binnay
	if (strcmp(current->comm, "a.out"))
		return;

	name_len = strncpy_from_user(filename, (const char *)regs->si, EMBEDDED_NAME_MAX);
	if (name_len < 0) {
		return;
	}
	filename[name_len] = '\0';

	pr_info("open -- Handle Post - proc=%s pid=%d filename=%s\n", current->comm, current->pid,
		filename);

	return;
}

static char recvfrom_symbol[MAX_SYMBOL_LEN] = "__sys_recvfrom";
static struct kprobe kp_recvfrom = {
	.symbol_name = recvfrom_symbol,
	.post_handler = recvfrom_post,
};

static char close_symbol[MAX_SYMBOL_LEN] = "__close_fd";
static struct kprobe kp_close = {
	.symbol_name = close_symbol,
	.pre_handler = close_pre,
};

static char write_symbol[MAX_SYMBOL_LEN] = "ksys_write";
static struct kprobe kp_write = {
	.symbol_name = write_symbol,
	.post_handler = write_post,
};

static char open_symbol[MAX_SYMBOL_LEN] = "do_sys_openat2";
static struct kprobe kp_open = {
	.symbol_name = open_symbol,
	.post_handler = open_post,
};

static struct kprobe *hook_list[] = {
	&kp_recvfrom, &kp_close, &kp_write, &kp_open, NULL,
};

int __init hook_init(void)
{
	int ret;
	struct kprobe **probe;

	for (probe = hook_list; *probe != NULL; probe++) {
		pr_info("kprobe register - %s\n", (*probe)->symbol_name);
		ret = register_kprobe(*probe);
		if (ret < 0) {
			pr_err("kprobe register err: %d\n", ret);
			return ret;
		}
	}

	return 0;
}

void __exit hook_exit(void)
{
	struct kprobe **probe;

	for (probe = hook_list; *probe != NULL; probe++) {
		unregister_kprobe(*probe);
		pr_info("kprobe unregister - %s\n", (*probe)->symbol_name);
	}
}

module_init(hook_init) module_exit(hook_exit) MODULE_LICENSE("GPL");
