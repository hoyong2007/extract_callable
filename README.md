# extract_callable
extract callable functions/basic block

# make kernel
for kernel version 4.14
```bash
git clone https://github.com/torvalds/linux.git
cd linux/
git checkout v4.14
make defconfig
make kvmconfig
```
### edit .config example
```
# Coverage collection.
CONFIG_KCOV=y

# Debug info for symbolization.
CONFIG_DEBUG_INFO=y

# Required for Debian Stretch
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y
```

```bash
make olddefconfig
make bzImage -j`nproc`
cd ../
mv linux/ linux-4.14/
```

# Usage
the <kernel_path> should be form like "linux-<version>" ex)linux-4.14
```bash
python get_all.py <kernel-path>
```
it would make $WORKDIR/result-$VERSION directory, and the analyzation result will be at this dir

* callable_with_result.lst
| the list with callable function:address
* callable_bb.lst
| it has callable basic block list
    ex) Function: <func>
        <start_addr>:<end_addr> <size>
        <start_addr>:<end_addr> <size>
        ...

* total_bb.lst : it has basic block list of every function
* out.json
| it has call graph that analyzed and extracted by radare2

