// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/btf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//#include <bpf/bpf_trace_helpers.h>
#include  <errno.h>

char _license[] SEC("license") = "GPL";

int seen_pin = 0;

#define MAX_ENTRIES 1024

/*
 * This map is for storing the DHCP relay server
 * IP address configured by user. It is received
 * as an argument by user program.
 * refered from dhcp_kern_xdp.c
*/
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, MAX_ENTRIES);
} policy_info_map SEC(".maps");


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

/* Input parameter: 'attr' is an anonymous struct used by BPF_MAP_CREATE command. 
					'attr' is a struct of type 'bpf_attr' defined in <bpf.h>.
					1. map_type: one of enum bpf_map_type
					2. key_size: size of key in bytes
					3. value_size: size of value in bytes
					4. max_entries: max number of entries in a map
					5. map_flags: BPF_MAP_CREATE related flags defined above.
						(BPF syscall commands,  enum bpf_cmd {BPF_MAP_CREATE, . . .})
						(flags for BPF_MAP_CREATE command: 
							Flags for accessing BPF object from syscall side
								BPF_F_RDONLY = (1U << 3),
								BPF_F_WRONLY = (1U << 4),
							Flag for stack_map, store build_id+offset instead of pointer
								BPF_F_STACK_BUILD_ID = (1U << 5)
							Flags for accessing BPF object from program side.
								BPF_F_RDONLY_PROG = (1U << 7),
								BPF_F_WRONLY_PROG = (1U << 8),
						)
					6. inner_map_fd: fd pointing to the inner map
					7. numa_node: numa node (effective only if BPF_F_NUMA_NODE is set).
					8. map_ifindex: ifindex of netdev to create on
					9. btf_fd: fd pointing to a BTF type data 
					10. btf_key_type_id: BTF type_id of the key
					11. btf_value_type_id: BTF type_id of the value
					12. btf_vmlinux_value_type_id: BTF type_id of a kernel-struct stored as the map value
					13. map_extra: Any per-map-type extra fields. BPF_MAP_TYPE_BLOOM_FILTER - the lowest 4 bits indicate the number of hash functions (if 0, the bloom filter will default to using 5 hash functions).
*/

SEC("lsm/bpf")
int BPF_PROG(sys_bpf_hook, int cmd, union bpf_attr *attr, unsigned int size)
{	
	__u32 *policy_val;
	int key = 0;

	bpf_printk("cmd: %d", cmd);
	bpf_printk("map_type: %u", attr->map_type);
	bpf_printk("key_size: %u", attr->key_size);
	//bpf_printk("value_size: %u",attr->value_size);
	//bpf_printk("value_size: %u",attr->map_extra);
	//bpf_printk("max_entries: %u", attr->max_entries);
	//bpf_printk("map_flags: %u",  attr->map_flags); 
	//bpf_printk("inner_map_fd: %u", attr->inner_map_fd);
	//bpf_printk("numa_node: %u\nmap_ifindex: %u\nbtf_fd: %u\n", attr->numa_node, attr->map_ifindex, attr->btf_fd);
	//bpf_printk("btf_key_type_id: %u\nbtf_value_type_id: %u\nbtf_vmlinux_value_type_id: %u\n", attr->btf_key_type_id, attr->btf_value_type_id, attr->btf_vmlinux_value_type_id);
	//char	map_name[BPF_OBJ_NAME_LEN]; BPF_OBJ_NAME_LEN 16U

	/* We need to allow a single pin action to pin ourselves after attach */
	/* Utkalika: Need to invoke policy_checker() which will return 0 or 1. 
	 * It will compare the capabilities of the program with the given list of the capabilities.*/
	/* Policy checker should be userspace, currently it is a dummy function*/
	/* print the input values*/
	//int flag = 1; 
	
	/*
	* if(cmd == BPF_PROG_LOAD){
	*	bpf_printk("log buffer: %s", (char *)attr->log_buf);
	* }
	*/
	policy_val = bpf_map_lookup_elem(&policy_info_map, &key);
	if (policy_val == NULL){
		return 1;
	}
	
	bpf_printk("policy value (Utkalika): %d", policy_val);

	if (cmd == BPF_OBJ_PIN && !seen_pin) {
		seen_pin = 1;
		return 0;
	}
	// if seen == 1 call policy_checker() : inputs: int cmd, union bpf_attr *attr and return: 0 or 1
	// cat /sys/kernel/debug/tracing/trace_pipe
	//bpf_printk("Policy violated");

	//return -EACCES;
	return 0;
}
