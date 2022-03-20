
## Build
Grab the submodule:
```
$ git submodule update --init --recursive
```

Switch to directory `src/`, and simply build the project with `make` command.

Make sure that you have LLVM and Clang installed, which are required to build the BPF program.

## Known issues
- bpftool
    The tool is shipped with ELF directly. However, if your libc is not of version 2.33, the loader will yell. I've tried build it statically, but didn't manage to succeed. Given this, if you can't run the tool correctly (which is required by the Makefile to build the BPF program), you can build it manually in the kernel tree with command `make tools/bpf/bpftool`, then the ELF can be found in the kernel tree under `tools/bpf/bpftool`.
