OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(abspath ../tools/bpftool)

LIBBPF_SRC := $(abspath ../libbpf/src)

LIBBPF_OBJ := $(abspath ../libbpf/libbpf.a)
INCLUDES := -I$(OUTPUT) -I$(abspath $(LIBBPF_SRC)/../)
PER_KERN_HEADER := $(OUTPUT)/vmlinux.h

# -freorder-blocks is for the sake of __builtin_expect
CFLAGS := -Wall -freorder-blocks -lstdc++ -pthread
COMMON_FLAGS :=
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

THIRD_PARTY_USER_SRCS := trace_helpers.c perfetto.cc

APPS = time_in_lb

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
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) $(THIRD_PARTY_USER_SRCS) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q) g++ $(CFLAGS) $^ -lelf -lz -o $@

$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

# Build user-space code
$(OUTPUT)/%.o: %.cc $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q) g++ $(CFLAGS) $(COMMON_FLAGS) $(INCLUDES) \
		-c $(filter %.cc,$^) -o $@

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(PER_KERN_HEADER):
	$(Q)$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@	

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) common.h $(PER_KERN_HEADER)| $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -mcpu=v3 -D__TARGET_ARCH_$(ARCH)               \
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
