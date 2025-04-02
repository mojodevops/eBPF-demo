BPF_CLANG=clang
BPFTOOL=bpftool

all: execve_trace

execve_trace.skel.h: execve_trace.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

execve_trace.bpf.o: execve_trace.bpf.c
	$(BPF_CLANG) -g -O2 -target bpf -I/usr/include/ -I/usr/include/linux/ -I/usr/include/x86_64-linux-gnu/linux/ -D__TARGET_ARCH_x86 -c $< -o $@

execve_trace: execve_trace.c execve_trace.skel.h
	$(BPF_CLANG) -g -O2 -Wall -I. -I/usr/include/ execve_trace.c -o execve_trace -lbpf -lelf -lz

clean:
	rm -f *.o *.skel.h execve_trace
