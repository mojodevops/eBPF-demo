APP = execve_trace
BPF_C = execve_trace.bpf.c
BPF_O = execve_trace.bpf.o

all: gen-build $(APP)

# 先编译 BPF 对象文件
CLANG_FLAGS = -O2 -target bpf -g  \
	-I/usr/include/bpf \
	-I/usr/include/linux \
	-I/usr/include/x86_64-linux-gnu/linux/ \
	-D__TARGET_ARCH_x86_64 \
	-Wno-address-of-packed-member   

$(BPF_O): $(BPF_C)
	clang $(CLANG_FLAGS) -c $< -o $@

# 生成骨架头文件
gen-build: $(BPF_O)
	bpftool gen skeleton $< > execve_trace.skel.h

# 编译用户态程序
$(APP): execve_trace.c
	clang -g -O2 -Wall -I/usr/include/ -c execve_trace.c -o execve_trace.o
	clang -g -O2 -Wall execve_trace.o -lbpf -lelf -lz -o $(APP)

clean:
	rm -f *.o $(APP) execve_trace.skel.h
