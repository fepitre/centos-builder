centos-builder
===

Script for generating a kickstarted CentOS 7 ISO

# Example:

```
$ ./generate-iso.sh --kickstart=/home/user/centos-hardened.ks --destdir=/home/user/iso
```
where `kickstart` is the kickstart file, `destdir` is the output directory.

If someone wants to use local CentOS 7 ISO, instead of letting the script downloading one, one can do
```
$ ./generate-iso.sh --kickstart=/home/user/centos-hardened.ks --destdir=/home/user/iso --sourceiso=/home/user/CentOS-7-x86_64-Minimal.iso
```
where `sourceiso` is the local CentOS 7 ISO to used.

> Remark: The output filename of created ISO is based on kickstart filename. In the example, the filename of the created ISO will be `CentOS-7-x86_64-centos-hardened.iso`.