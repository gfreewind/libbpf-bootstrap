/**
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * File              : whereispkt.c
 * Author            : Gao Feng <gfree.wind@outlook.com>
 * Date              : 2023-09-24
 * Last Modified Date: 2023-09-24
 */

#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "whereispkt.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}
int main(int argc, const char **argv)
{
	struct whereispkt_bpf *skel = NULL;
	int ret = 0;

	libbpf_set_print(libbpf_print_fn);

	skel = whereispkt_bpf__open();
	if (!skel) {
		fprintf(stderr, "Fail to open BPF skeleton");
		ret = -1;
		goto err1;
	}

	/* Load & verify BPF programs */
	ret = whereispkt_bpf__load(skel);
	if (ret) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	ret = whereispkt_bpf__attach(skel);
	if (ret) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (;;) {
		/* trigger our BPF program */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	whereispkt_bpf__destroy(skel);
err1:
	return ret;
}