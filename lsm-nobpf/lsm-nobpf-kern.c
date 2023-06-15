// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/btf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//#include <bpf/bpf_trace_helpers.h>
#include  <errno.h>

char _license[] SEC("license") = "GPL";

int seen_pin = 0;

/* BPF_OBJ_PIN
 *	Description
 *		Pin an eBPF program or map referred by the specified *bpf_fd*
 *		to the provided *pathname* on the filesystem.
 *
 *		The *pathname* argument must not contain a dot (".").
 *
 *		On success, *pathname* retains a reference to the eBPF object,
 *		preventing deallocation of the object when the original
 *		*bpf_fd* is closed. This allow the eBPF object to live beyond
 *		**close**\ (\ *bpf_fd*\ ), and hence the lifetime of the parent
 *		process.
 *
 *		Applying **unlink**\ (2) or similar calls to the *pathname*
 *		unpins the object from the filesystem, removing the reference.
 *		If no other file descriptors or filesystem nodes refer to the
 *		same object, it will be deallocated (see NOTES).
 *
 *		The filesystem type for the parent directory of *pathname* must
 *		be **BPF_FS_MAGIC**.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.

*/

SEC("lsm/bpf")
int BPF_PROG(sys_bpf_hook, int cmd, union bpf_attr *attr, unsigned int size)
{
	/* We need to allow a single pin action to pin ourselves after attach */
	/* Utkalika: Need to invoke policy_checker() which will return 0 or 1. It will compare the capabilities of the program with the given list of the capabilities.*/
	
	int flag = 1; 


	if (cmd == BPF_OBJ_PIN && !seen_pin && !flag) {
		seen_pin = 1;
		return 0;
	}
	bpf_printk("Policy violated");

	return -EACCES;
}
