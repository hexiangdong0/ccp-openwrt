# ccp-openwrt

环境：Ubuntu 20.04（编译OpenWrt源码），VirtualBox（安装OpenWrt）。

## 下载OpenWrt源码

https://github.com/openwrt/openwrt

不要下载master分支，可能编译不通过，下载稳定版本的代码，比如 https://github.com/openwrt/openwrt/tree/openwrt-21.02 。

## 编译源码

把此仓库拷贝到OpenWrt源码的package文件夹下。

然后切换到OpenWrt源码的根目录下，执行`make menuconfig`，在`Build the OpenWrt SK`上按y（这个SDK后面用来编译Rust代码，就是拥塞控制算法），在`kernel modules`-->`other modules`-->`kmod-tcp_ccp`上按m。

然后保存并退出menuconfig。

执行`make`，编译过程需要联网，编译需要大概2小时。

## 安装OpenWrt及ccp

用`openwrt-source-code/bin/targets/x86/64/openwrt-*.img.gz`解压出来的img安装OpenWrt（用官网下载的img好像无法安装编译出来的ccp），安装过程参考 https://openwrt.org/docs/guide-user/virtualization/virtualbox-vm 。

安装OpenWrt系统之后，将`openwrt-source-code/bin/targets/x86/64/packages/kmod-tcp_ccp*.ipk`上传到OpenWrt：

```
cd bin/targets/x86/64/packages
scp ./kmod-tcp_ccp*.ipk root@192.168.56.2:/tmp/
```

然后在OpenWrt中执行：

```
cd /tmp
opkg install ./kmod-tcp_ccp*.ipk
cd /lib/modules/<内核版本号>/
insmod ./tcp_ccp.ko
```

## 安装BBR算法

在Ubuntu安装好Rust编译工具：

```
 curl https://sh.rustup.rs -sSf | sh -s -- -y -v --default-toolchain nightly
```

克隆BBR仓库：

```
git clone https://github.com/ccp-project/ccp-kernel.git
```

### Rust 交叉编译设置

解压前面编译得到的SDK压缩包：`openwrt/bin/targets/x86/64/openwrt-sdk*.tar.xz`，并在Terminal切换到解压后的文件夹中。

设置环境变量：

```
PATH=$PATH:<SDK文件夹的绝对路径>/staging_dir/toolchain-x86_64_gcc-7.3.0_musl/bin
export PATH
export LC_ALL=C.UTF-8
```

设置交叉编译工具链

```
rustup target add x86_64-unknown-linux-musl
```

### 编译BBR

切换到BBR源码目录，执行：

```
cargo build --target x86_64-unknown-linux-musl --release
```

将`bbr/target/x86_64-unknown-linux-musl/release/bbr`上传到OpenWrt中，然后在OpenWrt中执行

```
./bbr --ipc netlink
```
