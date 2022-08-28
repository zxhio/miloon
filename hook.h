//===- hook.h - syscall hook ------------------------------------*- C++ -*-===//
//
/// \file
/// Syscall hook point handleer.
//
// Author:  zxh
// Date:    2022/08/21 17:00:11
//===----------------------------------------------------------------------===//

#pragma once

#include <linux/kprobes.h>

#define MAX_SYMBOL_LEN 64

// recvfrom kprobe
void __kprobes recvfrom_post(struct kprobe *, struct pt_regs *, unsigned long);

// close kprobe
int __kprobes close_pre(struct kprobe *, struct pt_regs *);

// write kprobe
void __kprobes write_post(struct kprobe *, struct pt_regs *, unsigned long);

// open kprobe
void __kprobes open_post(struct kprobe *, struct pt_regs *, unsigned long);