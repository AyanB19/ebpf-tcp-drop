BPF_OBJ = bpf_program/drop_tcp.o
USER_PROG = user_program/set_block_port

.PHONY: all clean

all: $(BPF_OBJ) $(USER_PROG)

$(BPF_OBJ): bpf_program/drop_tcp.c
	clang -O2 -target bpf -c $< -o $@

$(USER_PROG): user_program/set_block_port.c
	gcc -o $@ $< -lbpf

clean:
	rm -f $(BPF_OBJ) $(USER_PROG)
