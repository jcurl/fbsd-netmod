# Introduction

This repository is about experimenting with the FreeBSD network stack.
Development is done with FreeBSD 13.5. It may work with later versions of
FreeBSD.

## Building

Ensure that you have the Kernel sources at `/usr/src`.

```sh
$ git clone ssh://bitbucket/qnx/fbsd-netmod
$ cd fbsd-netmod/src
```

The file `build.sh` in the `src` directory does the work to build everything in
the `obj` folder. Any arguments you give it are passed on to the `make` command.

1. To build the sources:

   ```sh
   build.sh
   ```

   In the `obj` folder you'll find the file `showifn.ko`.

2. To clean the sources

   ```sh
   build.sh clean
   ```

## Installing the Kernel Module (testing)

I'm testing on a Raspberry Pi 4. I have `sudo` installed and configured. I'm
testing on the same machine that I build on to make it faster. This is however
dangerous, as a crash in the kernel can result in data loss.

```sh
$ sync
$ sudo kldload ./obj/showifn.ko
$ sudo dmesg
```

And then uninstall, so it can be rebuilt and tested again.

```sh
$ sudo kldunload ./obj/showifn.ko
```
