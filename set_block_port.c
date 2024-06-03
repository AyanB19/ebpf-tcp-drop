#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define BLOCK_PORT_MAP "/sys/fs/bpf/block_port_map"

int main(int argc, char **argv) {
    int map_fd;
    __u32 key = 0;
    __u16 port;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    port = (__u16)atoi(argv[1]);

    map_fd = bpf_obj_get(BLOCK_PORT_MAP);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open BPF map: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (bpf_map_update_elem(map_fd, &key, &port, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update BPF map: %s\n", strerror(errno));
        close(map_fd);
        return EXIT_FAILURE;
    }

    printf("Successfully updated port to %d\n", port);
    close(map_fd);
    return EXIT_SUCCESS;
}
