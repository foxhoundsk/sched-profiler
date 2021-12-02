OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(abspath ../tools/bpftool)

# FIXME: path/to/patched/kernel/tree
TREE:= $(abspath /home/arch/libbpf)
LIBBPF_SRC := $(abspath $(TREE)/tools/lib/bpf/)

# NOTE: this libbpf.a should be sched bpf flavored object
LIBBPF_OBJ := $(abspath $(TREE)/tools/lib/bpf/libbpf.a)
INCLUDES := -I$(OUTPUT) -I$(TREE)/tools/lib 
PER_KERN_HEADER := $(OUTPUT)/vmlinux.h

# the last flag is for the sake of __builtin_expect
CFLAGS := -g -Wall -freorder-blocks
COMMON_FLAGS :=
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

APPS = time_in_rq time_in_lb

ifeq ($(V),1)
        Q =
        msg =
else
        Q = @
        msg = @printf '  %-8s %s%s\n'                                   \
                      "$(1)"                                            \
                      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"       \
                      "$(if $(3), $(3))";
        MAKEFLAGS += --no-print-directory
endif

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build final application
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -o $@

$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

# Build user-space code
$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(COMMON_FLAGS) $(INCLUDES) \
		-c $(filter %.c,$^) -o $@

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(PER_KERN_HEADER):
	$(Q)$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@	

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) common.h $(PER_KERN_HEADER)| $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)               \
                     $(INCLUDES) $(COMMON_FLAGS) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@

# TODO: MAKE -C into kernel tree to build the lib
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1                      \
                   OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)                 \
                   INCLUDEDIR= LIBDIR= UAPIDIR=                              \
                   install

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
