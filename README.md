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