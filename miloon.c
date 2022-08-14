//===- miloon.c - kprobe module ---------------------------------*- C++ -*-===//
//
/// \file
///
//
// Author:  zxh
// Date:    2022/08/14 21:23:55
//===----------------------------------------------------------------------===//

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/file.h>
#include <net/inet_sock.h>
#include <linux/limits.h>

#define MAX_SYMBOL_LEN 64
static char symbol[MAX_SYMBOL_LEN] = "__sys_recvfrom";
module_param_string(symbol, symbol, sizeof(symbol), 0644);

static struct kprobe kp = {
	.symbol_name = symbol,
};

static int __kprobes handle_pre(struct kprobe *p, struct pt_regs *regs)
{
	pr_info("recvfrom -- Handle Pre - fd=%lu\n", regs->di);
	return 0;
}

static void __kprobes handle_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	int addr_len, fd, err;
	struct sockaddr_storage addr;
	struct sockaddr_in *in;
	uint8_t *addr_byte;
	struct socket *sock;

	fd = (int)regs->di;
	pr_info("recvfrom -- Handle Post - fd=%d, ret_val=0x%lx\n", fd, regs->ax);

	if (regs->r9) {
		if (copy_from_user(&addr_len, (int *)regs->r9, sizeof(addr_len)))
			return;
		pr_info("recvfrom -- Handle Post - addr_len=%d\n", addr_len);
		if (copy_from_user(&addr, (struct sockaddr *)regs->r8, addr_len))
			return;
		if (addr.ss_family == AF_INET) {
			// TODO: trans to user space
			in = (struct sockaddr_in *)&addr;
			addr_byte = (uint8_t *)&in->sin_addr.s_addr;
			pr_info("recvfrom -- Handle Post - remote_addr=%d.%d.%d.%d:%d\n",
				addr_byte[0], addr_byte[1], addr_byte[2], addr_byte[3],
				ntohs(in->sin_port));
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
		addr_byte = (uint8_t *)&in->sin_addr.s_addr;
		pr_info("recvfrom -- Handle Post - getpeername remote_addr=%d.%d.%d.%d:%d\n",
			addr_byte[0], addr_byte[1], addr_byte[2], addr_byte[3],
			ntohs(in->sin_port));
	}

out:
	sockfd_put(sock);
}

static int __exit kprobe_init(void)
{
	int ret;

	kp.pre_handler = handle_pre;
	kp.post_handler = handle_post;
	kp.fault_handler = NULL;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_info("kprobe register err: %d\n", ret);
		return ret;
	}
	pr_info("kprobe register ok\n");

	return 0;
}

static void __exit kprobe_exit(void)
{
	unregister_kprobe(&kp);
	pr_info("kprobe unregister\n");
}

static char func_name[NAME_MAX] = "__sys_recvfrom";
module_param_string(func, func_name, NAME_MAX, S_IRUGO);
MODULE_PARM_DESC(func, "Function to kretprobe; this module will report the"
		       " function's execution time");

/* per-instance private data */
struct my_data {
};

/* Here we use the entry_hanlder to timestamp function entry */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}
NOKPROBE_SYMBOL(entry_handler);

/*
 * Return-probe handler: Log the return value and duration. Duration may turn
 * out to be zero consistently, depending upon the granularity of time
 * accounting on the platform.
 */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned long retval = regs_return_value(regs);
	// int addr_len, err;

	// if (regs->r9) {
	// 	err = copy_from_user(&addr_len, (int *)regs->r9, sizeof(addr_len));
	// 	if (err)
	// 		return err;
	// 	pr_info("recvfrom -- Handle Ret - addr_len=%d\n", addr_len);
	// }

	pr_info("recvfrom -- Handle Ret - retval=%lu\n", retval);
	return 0;
}
NOKPROBE_SYMBOL(ret_handler);

static struct kretprobe my_kretprobe = {
	.handler = ret_handler,
	.entry_handler = entry_handler,
	.data_size = sizeof(struct my_data),
	/* Probe up to 20 instances concurrently. */
	.maxactive = 20,
};

static int __init kretprobe_init(void)
{
	int ret;

	my_kretprobe.kp.symbol_name = func_name;
	ret = register_kretprobe(&my_kretprobe);
	if (ret < 0) {
		pr_err("register_kretprobe failed, returned %d\n", ret);
		return -1;
	}
	pr_info("Planted return probe at %s: %p\n", my_kretprobe.kp.symbol_name,
		my_kretprobe.kp.addr);
	return 0;
}

static void __exit kretprobe_exit(void)
{
	unregister_kretprobe(&my_kretprobe);
	pr_info("kretprobe at %p unregistered\n", my_kretprobe.kp.addr);

	/* nmissed > 0 suggests that maxactive was set too low. */
	pr_info("Missed probing %d instances of %s\n", my_kretprobe.nmissed,
		my_kretprobe.kp.symbol_name);
}

static int __init probe_init(void)
{
	kprobe_init();
	kretprobe_init();
	return 0;
}

static void __exit probe_exit(void)
{
	kprobe_exit();
	kretprobe_exit();
}

module_init(probe_init) module_exit(probe_exit) MODULE_LICENSE("GPL");