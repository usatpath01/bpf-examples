#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "lsmnobpf.h"


//refered from dhcp_user_xdp.c
#define POLICY_MAP "policy_info_map"
#define LSMNOBPF_OBJ "lsm-nobpf-kern.o"

int main(int argc, char **argv)
{
	struct bpf_object *obj = NULL;
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	int err = 0, fd;
	char buf[100];
	ssize_t len;
	char *c;

	// Utkalika - Start
	struct policy_kv pkv;
	int key = 0;
	int value = 20;
	struct bpf_map *map = NULL;
	int map_fd;
	// Utkalika - End

	fd = open("/sys/kernel/security/lsm", O_RDONLY);
        if (fd < 0) {
		err = -errno;
		printf("Error opening /sys/kernel/security/lsm ('%s') - securityfs "
		       "not mounted?\n",
		       strerror(-err));
		goto out;
        }

	len = read(fd, buf, sizeof(buf));
	if (len == -1) {
		err = -errno;
		printf("Error reading /sys/kernel/security/lsm: %s\n",
		       strerror(-err));
		close(fd);
		goto out;
	}
	close(fd);
	buf[sizeof(buf)-1] = '\0';
	c = strstr(buf, "bpf");
	if (!c) {
		printf("BPF LSM not loaded - make sure CONFIG_LSM or lsm kernel "
		       "param includes 'bpf'!\n");
		err = -EINVAL;
		goto out;
	}

    obj = bpf_object__open_file("lsm-nobpf-kern.o", NULL);
	//snprintf(obj->log_buf,9, "Utkalika");
	
	err = libbpf_get_error(obj);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		printf("Error opening file: %s\n", buf);
		goto out;
	}

	err = bpf_object__load(obj);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		printf("Error loading: %s\n", buf);
		goto out;
	}

	// Utkalika - Start
	/* read the map from prog object file and update the policy value to the map */
	map = bpf_object__find_map_by_name(obj, POLICY_MAP);
	err = libbpf_get_error(map);
	if (err) {
		fprintf(stderr, "Could not find map %s in %s: %s\n", POLICY_MAP,
			LSMNOBPF_OBJ, strerror(err));
		map = NULL;
		exit(-1);
	}
	else{
		printf("map updated successfully");
	}
	map_fd = bpf_map__fd(map);
	if (map_fd < 0) {
		fprintf(stderr, "Could not get map fd\n");
		exit(-1);
	}
	err = bpf_map_update_elem(map_fd, &key, &pkv.value, BPF_ANY);
	if (err) {
		fprintf(stderr, "Could not update map %s in %s\n", POLICY_MAP,
			LSMNOBPF_OBJ);
		exit(-1);
	}
	// Utkalika - End

	prog = bpf_object__next_program(obj, NULL);
	if (!prog) {
		printf("No program!\n");
		err = -ENOENT;
		goto out;
	}

	link = bpf_program__attach(prog);
	err = libbpf_get_error(link);
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		printf("Error attaching: %s\n", buf);
		goto out;
	}

	err = bpf_link__pin(link, "/sys/fs/bpf/lsm-nobpf");
	if (err) {
		libbpf_strerror(err, buf, sizeof(buf));
		printf("Error pinning: %s\n", buf);
		goto out;
	}

	printf("The bpf() syscall is now disabled - delete /sys/fs/bpf/lsm-nobpf to re-enable\n");

out:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	if (err)
		return 1;
	return 0;
}
