// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/taskstats.h>
#include <linux/string.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

SEC("tp/skb/consume_skb")
int handle_tp(void *ctx)
{
	char name[16];

	if (bpf_get_current_comm(name, sizeof(name)) != 0) {
		strcpy(name, "unkwown");
	}
	bpf_printk("%s:Got one consume_skb\n", name);

	return 0;
}