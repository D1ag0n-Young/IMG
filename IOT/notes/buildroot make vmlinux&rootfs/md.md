# buildroot制作vmlinux和rootfs
搞异构环境下的程序，不管是比赛pwn，还是日常使用都需要各种环境，比赛那就更需要提前准备好环境了，我也是历经千辛万苦找到了简单又快速的编译生成qemu启动各个架构所依赖的vmlinux和rootfs的方法，以及qemu和宿主机通信的方法，在此记录一下。
# buildroot编译vmlinux和rootfs
这里以编译aarch64 LSB为例，记录编译它的过程，用到的工具就是[buildroot](https://buildroot.org/)，很强大的工具，不仅可以制作rootfs，还可以生成内核镜像vmlinux，而且最主要的是他可以选择给rootfs预先安装哪些package，等很多强大的功能，等你去探索。
编译前先安装好依赖：
`apt install sed make binutils build-essential gcc g++ bash patch gzip bzip2 perl tar cpio unzip rsync file bc  ncurses-dev`
## 下载buildroot及配置config
去github上下载后解压，进入到buildroot目录，运行`ls configs`查看支持的默认架构，我们要生成qemu的镜像和vmlinux，所以选择`qemu_aarch64_virt_defconfig`,似乎这里就这一个，如果没找到合适的，可以自行`make menuconfig`去配置。运行`make qemu_aarch64_virt_defconfig`，之后运行`make menuconfig`，去配置额外的选项。
```bash
$ ls configs
aarch64_efi_defconfig                     ci20_defconfig                          licheepi_zero_defconfig                         orangepi_rk3399_defconfig           qemu_x86_defconfig
acmesystems_aria_g25_128mb_defconfig      csky_gx6605s_defconfig                  linksprite_pcduino_defconfig                    orangepi_win_defconfig              qemu_xtensa_lx60_defconfig
acmesystems_aria_g25_256mb_defconfig      cubieboard2_defconfig                   microchip_sama5d27_wlsom1_ek_mmc_defconfig      orangepi_zero_defconfig             qemu_xtensa_lx60_nommu_defconfig
acmesystems_arietta_g25_128mb_defconfig   engicam_imx6qdl_icore_defconfig         microchip_sama5d27_wlsom1_ek_mmc_dev_defconfig  orangepi_zero_plus2_defconfig       raspberrypi0_defconfig
acmesystems_arietta_g25_256mb_defconfig   engicam_imx6qdl_icore_qt5_defconfig     minnowboard_max_defconfig                       orangepi_zero_plus_defconfig        raspberrypi0w_defconfig
amarula_a64_relic_defconfig               engicam_imx6qdl_icore_rqs_defconfig     minnowboard_max-graphical_defconfig             pandaboard_defconfig                raspberrypi2_defconfig
amarula_vyasa_rk3288_defconfig            engicam_imx6ul_geam_defconfig           mx25pdk_defconfig                               pcengines_apu2_defconfig            raspberrypi3_64_defconfig
andes_ae3xx_defconfig                     engicam_imx6ul_isiot_defconfig          mx51evk_defconfig                               pc_x86_64_bios_defconfig            raspberrypi3_defconfig
arcturus_ucls1012a_defconfig              freescale_imx28evk_defconfig            mx53loco_defconfig                              pc_x86_64_efi_defconfig             raspberrypi3_qt5we_defconfig
arcturus_ucp1020_defconfig                freescale_imx6dlsabreauto_defconfig     mx6cubox_defconfig                              pine64_defconfig                    raspberrypi4_64_defconfig
armadeus_apf27_defconfig                  freescale_imx6dlsabresd_defconfig       mx6sx_udoo_neo_defconfig                        pine64_sopine_defconfig             raspberrypi4_defconfig
armadeus_apf28_defconfig                  freescale_imx6qsabreauto_defconfig      mx6udoo_defconfig                               qemu_aarch64_virt_defconfig         raspberrypi_defconfig
armadeus_apf51_defconfig                  freescale_imx6qsabresd_defconfig        nanopc_t4_defconfig                             qemu_arm_versatile_defconfig        riotboard_defconfig
arm_foundationv8_defconfig                freescale_imx6sxsabresd_defconfig       nanopi_m1_defconfig                             qemu_arm_versatile_nommu_defconfig  rock_pi_4_defconfig
arm_juno_defconfig                        freescale_imx6ullevk_defconfig          nanopi_m1_plus_defconfig                        qemu_arm_vexpress_defconfig         rock_pi_n10_defconfig
asus_tinker_rk3288_defconfig              freescale_imx7dsabresd_defconfig        nanopi_m4_defconfig                             qemu_arm_vexpress_tz_defconfig      rock_pi_n8_defconfig
at91sam9260eknf_defconfig                 freescale_imx8mmevk_defconfig           nanopi_neo4_defconfig                           qemu_csky610_virt_defconfig         rockpro64_defconfig
at91sam9g20dfc_defconfig                  freescale_imx8mnevk_defconfig           nanopi_neo_defconfig                            qemu_csky807_virt_defconfig         roc_pc_rk3399_defconfig
at91sam9g45m10ek_defconfig                freescale_imx8mqevk_defconfig           nanopi_r1_defconfig                             qemu_csky810_virt_defconfig         roseapplepi_defconfig
at91sam9rlek_defconfig                    freescale_imx8qmmek_defconfig           nexbox_a95x_defconfig                           qemu_csky860_virt_defconfig         s6lx9_microboard_defconfig
at91sam9x5ek_defconfig                    freescale_imx8qxpmek_defconfig          nitrogen6sx_defconfig                           qemu_m68k_mcf5208_defconfig         sheevaplug_defconfig
at91sam9x5ek_dev_defconfig                freescale_p1025twr_defconfig            nitrogen6x_defconfig                            qemu_m68k_q800_defconfig            snps_aarch64_vdk_defconfig
at91sam9x5ek_mmc_defconfig                freescale_t1040d4rdb_defconfig          nitrogen7_defconfig                             qemu_microblazebe_mmu_defconfig     snps_arc700_axs101_defconfig
at91sam9x5ek_mmc_dev_defconfig            freescale_t2080_qds_rdb_defconfig       nitrogen8m_defconfig                            qemu_microblazeel_mmu_defconfig     snps_archs38_axs103_defconfig
atmel_sama5d27_som1_ek_mmc_dev_defconfig  friendlyarm_nanopi_a64_defconfig        nitrogen8mm_defconfig                           qemu_mips32r2el_malta_defconfig     snps_archs38_haps_defconfig
atmel_sama5d2_xplained_mmc_defconfig      friendlyarm_nanopi_neo2_defconfig       nitrogen8mn_defconfig                           qemu_mips32r2_malta_defconfig       snps_archs38_hsdk_defconfig
atmel_sama5d2_xplained_mmc_dev_defconfig  friendlyarm_nanopi_neo_plus2_defconfig  odroidc2_defconfig                              qemu_mips32r6el_malta_defconfig     snps_archs38_vdk_defconfig
atmel_sama5d3xek_defconfig                galileo_defconfig                       odroidxu4_defconfig                             qemu_mips32r6_malta_defconfig       socrates_cyclone5_defconfig
atmel_sama5d3_xplained_defconfig          globalscale_espressobin_defconfig       olimex_a10_olinuxino_lime_defconfig             qemu_mips64el_malta_defconfig       solidrun_clearfog_defconfig
atmel_sama5d3_xplained_dev_defconfig      grinn_chiliboard_defconfig              olimex_a13_olinuxino_defconfig                  qemu_mips64_malta_defconfig         solidrun_clearfog_gt_8k_defconfig
atmel_sama5d3_xplained_mmc_defconfig      grinn_liteboard_defconfig               olimex_a20_olinuxino_lime2_defconfig            qemu_mips64r6el_malta_defconfig     solidrun_macchiatobin_defconfig
atmel_sama5d3_xplained_mmc_dev_defconfig  hifive_unleashed_defconfig              olimex_a20_olinuxino_lime_defconfig             qemu_mips64r6_malta_defconfig       stm32f429_disco_defconfig
atmel_sama5d4_xplained_defconfig          imx23evk_defconfig                      olimex_a20_olinuxino_micro_defconfig            qemu_nios2_10m50_defconfig          stm32f469_disco_defconfig
atmel_sama5d4_xplained_dev_defconfig      imx6-sabreauto_defconfig                olimex_a33_olinuxino_defconfig                  qemu_or1k_defconfig                 stm32mp157a_dk1_defconfig
atmel_sama5d4_xplained_mmc_defconfig      imx6-sabresd_defconfig                  olimex_a64_olinuxino_defconfig                  qemu_ppc64_e5500_defconfig          stm32mp157c_dk2_defconfig
atmel_sama5d4_xplained_mmc_dev_defconfig  imx6-sabresd_qt5_defconfig              olimex_imx233_olinuxino_defconfig               qemu_ppc64le_pseries_defconfig      toradex_apalis_imx6_defconfig
bananapi_m1_defconfig                     imx6slevk_defconfig                     olpc_xo175_defconfig                            qemu_ppc64_pseries_defconfig        ts4900_defconfig
bananapi_m2_plus_defconfig                imx6sx-sdb_defconfig                    olpc_xo1_defconfig                              qemu_ppc_g3beige_defconfig          ts5500_defconfig
bananapi_m2_ultra_defconfig               imx6ulevk_defconfig                     openblocks_a6_defconfig                         qemu_ppc_mac99_defconfig            ts7680_defconfig
bananapi_m2_zero_defconfig                imx6ullevk_defconfig                    orangepi_lite2_defconfig                        qemu_ppc_mpc8544ds_defconfig        wandboard_defconfig
bananapi_m64_defconfig                    imx6ulpico_defconfig                    orangepi_lite_defconfig                         qemu_ppc_virtex_ml507_defconfig     warp7_defconfig
bananapro_defconfig                       imx7dpico_defconfig                     orangepi_one_defconfig                          qemu_riscv32_virt_defconfig         warpboard_defconfig
beagleboardx15_defconfig                  imx7d-sdb_defconfig                     orangepi_one_plus_defconfig                     qemu_riscv64_virt_defconfig         zynq_microzed_defconfig
beagleboneai_defconfig                    imx8mmpico_defconfig                    orangepi_pc2_defconfig                          qemu_s390x_defconfig                zynqmp_zcu106_defconfig
beaglebone_defconfig                      imx8mpico_defconfig                     orangepi_pc_defconfig                           qemu_sh4eb_r2d_defconfig            zynq_qmtech_defconfig
beaglebone_qt5_defconfig                  imx8mqevk_defconfig                     orangepi_pc_plus_defconfig                      qemu_sh4_r2d_defconfig              zynq_zc706_defconfig
beelink_gs1_defconfig                     kontron_smarc_sal28_defconfig           orangepi_plus_defconfig                         qemu_sparc64_sun4u_defconfig        zynq_zed_defconfig
chromebook_elm_defconfig                  lafrite_defconfig                       orangepi_prime_defconfig                        qemu_sparc_ss10_defconfig
chromebook_snow_defconfig                 lego_ev3_defconfig                      orangepi_r1_defconfig                           qemu_x86_64_defconfig
```
## 配置Target options
这里可以选择大小端,选择`Target options`:
```bash
  │ │                                           Target Architecture (AArch64 (little endian))  --->                                                       │ │  
  │ │                                           Target Binary Format (ELF)  --->                                                                          │ │  
  │ │                                           Target Architecture Variant (cortex-A53)  --->                                                            │ │  
  │ │                                           Floating point strategy (FP-ARMv8)  --->  
```
## 配置Toolchain
可以按如下选择，如果有额外的需求可以复选。`Thread library debugging`为安装gdbserver必选项。
```
  │ ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │  
  │ │                                           Toolchain type (Buildroot toolchain)  --->                                                                │ │  
  │ │                                           *** Toolchain Buildroot Options ***                                                                       │ │  
  │ │                                       (buildroot) custom toolchain vendor name                                                                      │ │  
  │ │                                           C library (uClibc-ng)  --->                                                                               │ │  
  │ │                                           *** Kernel Header Options ***                                                                             │ │  
  │ │                                           Kernel Headers (Same as kernel being built)  --->                                                         │ │  
  │ │                                           Custom kernel headers series (5.10.x or later)  --->                                                      │ │  
  │ │                                           *** uClibc Options ***                                                                                    │ │  
  │ │                                       (package/uclibc/uClibc-ng.config) uClibc configuration file to use?                                           │ │  
  │ │                                       ()  Additional uClibc configuration fragment files                                                            │ │  
  │ │                                       [*] Enable WCHAR support                                                                                      │ │  
  │ │                                       [ ] Enable toolchain locale/i18n support                                                                      │ │  
  │ │                                           Thread library implementation (Native POSIX Threading (NPTL))  --->                                       │ │  
  │ │                                       [*] Thread library debugging                                                                                  │ │  
  │ │                                       [*] Enable stack protection support                                                                           │ │  
  │ │                                       [*] Compile and install uClibc utilities                                                                      │ │  
  │ │                                           *** Binutils Options ***                                                                                  │ │  
  │ │                                           Binutils Version (binutils 2.35.2)  --->                                                                  │ │  
  │ │                                       ()  Additional binutils options                                                                               │ │  
  │ │                                           *** GCC Options ***                                                                                       │ │  
  │ │                                           GCC compiler Version (gcc 9.x)  --->                                                                      │ │  
  │ │                                       ()  Additional gcc options                                                                                    │ │  
  │ │                                       [*] Enable C++ support                                                                                        │ │  
  │ │                                       [ ] Enable Fortran support                                                                                    │ │  
  │ │                                       [ ] Enable compiler link-time-optimization support                                                            │ │  
  │ │                                       [ ] Enable compiler OpenMP support                                                                            │ │  
  │ │                                       [ ] Enable graphite support                                                                                   │ │  

```
## 配置Target packages 
这里面可以选择一些系统需要的package，比较方便，这里选择安装gdb、dt、strace，其他的看情况可以复选。
选择`Show packages that are also provided by busybox`,进入` Debugging, profiling and benchmark`，安装gdb、dt、strace
```
  │ ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │  
  │ │                                       -*- BusyBox                                                                                                   │ │  
  │ │                                       (package/busybox/busybox.config) BusyBox configuration file to use?                                           │ │  
  │ │                                       ()    Additional BusyBox configuration fragment files                                                         │ │  
  │ │                                       [*]   Show packages that are also provided by busybox                                                         │ │  
  │ │                                       [ ]   Individual binaries                                                                                     │ │  
  │ │                                       [ ]   Install the watchdog daemon startup script                                                              │ │  
  │ │                                           Audio and video applications  --->                                                                        │ │  
  │ │                                           Compressors and decompressors  --->                                                                       │ │  
  │ │                                           Debugging, profiling and benchmark  --->                                                                  │ │  
  │ │                                           Development tools  --->                                                                                   │ │  
  │ │                                           Filesystem and flash utilities  --->                                                                      │ │  
  │ │                                           Fonts, cursors, icons, sounds and themes  --->                                                            │ │  
  │ │                                           Games  --->                                                                                               │ │  
  │ │                                           Graphic libraries and applications (graphic/text)  --->                                                   │ │  
  │ │                                           Hardware handling  --->                                                                                   │ │  
  │ │                                           Interpreter languages and scripting  --->                                                                 │ │  
  │ │                                           Libraries  --->                                                                                           │ │  
  │ │                                           Mail  --->                                                                                                │ │  
  │ │                                           Miscellaneous  --->                                                                                       │ │  
  │ │                                           Networking applications  --->                                                                             │ │  
  │ │                                           Package managers  --->                                                                                    │ │  

  │ ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │  
  │ │                                       [ ] babeltrace2                                                                                               │ │  
  │ │                                       [ ] blktrace                                                                                                  │ │  
  │ │                                       [ ] bonnie++                                                                                                  │ │  
  │ │                                       [ ] cache-calibrator                                                                                          │ │  
  │ │                                           *** clinfo needs an OpenCL provider ***                                                                   │ │  
  │ │                                       [ ] coremark                                                                                                  │ │  
  │ │                                       [ ] coremark-pro                                                                                              │ │  
  │ │                                           *** dacapo needs OpenJDK ***                                                                              │ │  
  │ │                                       [ ] delve                                                                                                     │ │  
  │ │                                       [ ] dhrystone                                                                                                 │ │  
  │ │                                       [ ] dieharder                                                                                                 │ │  
  │ │                                       [ ] dmalloc                                                                                                   │ │  
  │ │                                       [ ] dropwatch                                                                                                 │ │  
  │ │                                       [ ] dstat                                                                                                     │ │  
  │ │                                       [*] dt                                                                                                        │ │  
  │ │                                       [ ] duma                                                                                                      │ │  
  │ │                                       [ ] fio                                                                                                       │ │  
  │ │                                           *** fwts needs a glibc toolchain w/ wchar, threads, dynamic library ***                                   │ │  
  │ │                                       [*] gdb                                                                                                       │ │  
  │ │                                       -*-   gdbserver                                                                                               │ │  
  │ │                                       [ ]   full debugger                                                                                           │ │  
  │ │                                       [ ] google-breakpad                                                                                           │ │  

```
如果想安装一些有的package但是这里没有显示，就使用`/`来搜索想安装的包，如gdb,按`/`,输入gdb回车，这里会提示gdb的location和依赖选项，只要将依赖选项选中就可以看到所需的package出来了。
```
┌──────────────────────────────────────────────────────────────────── Search Results ─────────────────────────────────────────────────────────────────────┐
  │ Symbol: BR2_GDB_VERSION [=9.2]                                                                                                                          │  
  │ Type  : string                                                                                                                                          │  
  │   Defined at package/gdb/Config.in.host:85                                                                                                              │  
  │   Depends on: BR2_PACKAGE_GDB [=y] || BR2_PACKAGE_HOST_GDB [=n]                                                                                         │  
  │                                                                                                                                                         │  
  │                                                                                                                                                         │  
  │ Symbol: BR2_GDB_VERSION_10 [=n]                                                                                                                         │  
  │ Type  : bool                                                                                                                                            │  
  │ Prompt: gdb 10.x                                                                                                                                        │  
  │   Location:                                                                                                                                             │  
  │     -> Toolchain                                                                                                                                        │  
  │ (1)   -> Build cross gdb for the host (BR2_PACKAGE_HOST_GDB [=n])                                                                                       │  
  │         -> GDB debugger Version (<choice> [=n])                                                                                                         │  
  │   Defined at package/gdb/Config.in.host:77                                                                                                              │  
  │   Depends on: <choice>                                                                                                                                  │  

```
接着选择`Networking applications`，选择netcat、nmap进行安装，其他根据自己需要安装：
```
  │ │                                       [ ] netatalk                                                                                                  │ │  
  │ │                                       [ ] netcalc                                                                                                   │ │  
  │ │                                       [*] netcat                                                                                                    │ │  
  │ │                                           *** netcat-openbsd needs a glibc toolchain w/ dynamic library, threads, headers >= 3.12 ***               │ │  
  │ │                                       [ ] netplug                                                                                                   │ │  
  │ │                                       [ ] netsnmp                                                                                                   │ │  
  │ │                                       [ ] netstat-nat                                                                                               │ │  
  │ │                                           *** NetworkManager needs udev /dev management and a glibc toolchain w/ headers >= 3.2, dynamic library, wc│ │  
  │ │                                       [ ] nfacct                                                                                                    │ │  
  │ │                                       [ ] nftables                                                                                                  │ │  
  │ │                                       [ ] nginx  ----                                                                                               │ │  
  │ │                                       [ ] ngircd                                                                                                    │ │  
  │ │                                       [ ] ngrep                                                                                                     │ │  
  │ │                                       [ ] nload                                                                                                     │ │  
  │ │                                       [*] nmap                                                                                                      │ │  
  │ │                                       [*]   install ncat                                                                                            │ │  
  │ │                                             *** ndiff needs Python 2.x ***                                                                          │ │  
  │ │                                       [ ]   install nmap                                                                                            │ │  
  │ │                                       [*]   install nping                                                                                           │ │  
  │ │                                       [ ] noip                                                                                                      │ │  
  │ │                                       [ ] ntp                                                                                                       │ │  

```
## 配置system image
这里配置生成镜像的格式、压缩方式等，这里选择ext4，cpio，其他可根据需要选择：
```
  │ ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │  
  │ │                                       [ ] axfs root filesystem                                                                                      │ │  
  │ │                                       [ ] btrfs root filesystem                                                                                     │ │  
  │ │                                       [ ] cloop root filesystem for the target device                                                               │ │  
  │ │                                       [*] cpio the root filesystem (for use as an initial RAM filesystem)                                           │ │  
  │ │                                             Compression method (no compression)  --->                                                               │ │  
  │ │                                       [ ]   Create U-Boot image of the root filesystem                                                              │ │  
  │ │                                       [ ] cramfs root filesystem                                                                                    │ │  
  │ │                                       [ ] erofs root filesystem                                                                                     │ │  
  │ │                                       [*] ext2/3/4 root filesystem                                                                                  │ │  
  │ │                                             ext2/3/4 variant (ext4)  --->                                                                           │ │  
  │ │                                       (rootfs) filesystem label                                                                                     │ │  
  │ │                                       (200M) exact size                                                                                             │ │  
  │ │                                       (0)   exact number of inodes (leave at 0 for auto calculation)                                                │ │  
  │ │                                       (5)   reserved blocks percentage                                                                              │ │  
  │ │                                       (-O ^64bit) additional mke2fs options                                                                         │ │  
  │ │                                             Compression method (no compression)  --->                                                               │ │ 
```
这些配置好后基本就可以了，直接`make`等待编译完成就可以看到`buildroot/output/images`下会生成至少三个文件:vmlinux、rootfs.ext4、start-qemu.sh(可能没有vmlinux，为Image等，都差不多其实)
注意：在编译过程中会下载gdb、linux源码等大文件可能会非常的慢，可以开启socket5代理，下载完，开启代理后可能会出现类似`address_ipv6`的报错，具体记不清了，此时关闭socket代理，继续make执行即可。
# 配置qemu和host主机网络
首先安装工具`sudo apt-get install uml-utilities bridge-utils`。
关于qemu和宿主机网络通信，我也查了好多，最后找到一中比较简单的桥接的配置方法。运行脚本`sudo ./qemu-ifup`
```
#qemu-ifup
#!/bin/sh

brctl addbr br0

tunctl -t tap100

ifconfig tap100 0.0.0.0 up

ifconfig br0 192.168.1.1 up

brctl addif br0 tap100

echo 1 > /proc/sys/net/ipv4/ip_forward
```
修改start-qemu.sh如下：
```bash
#!/bin/sh
(
BINARIES_DIR="${0%/*}/"
cd ${BINARIES_DIR}

if [ "${1}" = "serial-only" ]; then
    EXTRA_ARGS='-nographic'
else
    EXTRA_ARGS=''
fi

export PATH="/home/yrl/buildroot-2021.02.4/output/host/bin:${PATH}"
#exec qemu-system-aarch64 -M virt -cpu cortex-a53 -nographic -smp 1 -kernel Image -append "rootwait root=/dev/vda console=ttyAMA0" -netdev user,id=eth0 -device virtio-net-device,netdev=eth0 -drive file=rootfs.ext4,if=none,format=raw,id=hd0 -device virtio-blk-device,drive=hd0  ${EXTRA_ARGS} 
exec qemu-system-aarch64 -M virt -cpu cortex-a53 -nographic -smp 1 -kernel Image -append "rootwait root=/dev/vda console=ttyAMA0" -drive file=rootfs.ext4,if=none,format=raw,id=hd0 -device virtio-blk-device,drive=hd0  ${EXTRA_ARGS} -net nic,macaddr=00:16:3e:00:00:01 -net tap,ifname=tap100,script=no
)
```
其实就是改变了qemu的网络连接方式，由`-net user`变成了`-net tap`去除了`-netdev user,id=eth0 -device virtio-net-device,netdev=eth0`添加了`-net nic,macaddr=00:16:3e:00:00:01 -net tap,ifname=tap100,script=no`,这两种方式（user模式、桥接tap模式）都能与宿主机通信，但是用法不一样：
## user模式
```bash
-netdev user,id=id[,option][,option][,...]
-net user[,option][,option][,...]

默认创建一个dhcp服务器地址是10.0.2.15
其中常见的选项（option）及其意义如下：
• vlan=n，将用户模式网络栈连接到编号为n的VLAN中（默认值为0）。
• name=name，分配一个在QEMU monitor中会用到的名字（如在monitor的“info network”命令中 可看到这个网卡的name）。
• net=addr[/mask]，设置客户机可以看到的IP地址（客户机所在子网），其默认值是10.0.2.0/24。其中，子网掩码（mask）有两种形式可选，一种是类似于255.255.255.0这样地址，另一种是32位IP地址中前面被置位为1的位数（如10.0.2.0/24）。
• host=addr，指定客户机可见宿主机的地址，默认值为客户机所在网络的第2个IP地址（如10.0.2.2）。
• restrict=y|yes|n|no，如果将此选项打开（为y或yes），则客户机将会被隔离，客户机不能与宿主机通信，其IP数据包也不能通过宿主机而路由到外部网络中。这个选项不会影响“hostfwd”显示地指定的转发规则，“hostfwd”选项始终会生效。默认值为n或no，不会隔离客户机。
• hostname=name，设置在宿主机DHCP服务器中保存的客户机主机名。
• dhcpstart=addr，设置能够分配给客户机的第一个IP，在QEMU内嵌的DHCP服务器有16个IP地址可供分配。在客户机中IP地址范围的默认值是子网中的第15到第30个IP地址（如10.0.2.15 ~ 10.0.2.30）。
• dns=addr，指定虚拟DNS的地址，这个地址必须与宿主机地址（在“host=addr”中指定的）不相同，其默认值是网络中的第3个IP地址（如10.0.2.3）。
• tftp=dir，激活QEMU内嵌的TFTP服务器，目录dir是TFTP服务的根目录。不过，在客户机使用TFTP客户端连接TFTP服务后需要使用binary模式来操作。
• hostfwd=[tcp|udp]:[hostaddr]:hostport-[guestaddr]:guestport，将访问宿主机的hostpot端口的TCP/UDP连接重定向到客户机（IP为guestaddr）的guestport端口上。如果没有设置guestaddr，那么默认使用x.x.x.15（DHCP服务器可分配的第一个IP地址）。如果指定了hostaddr的值，则可以根据宿主机上的一个特定网络接口的IP端口来重定向。如果没有设置连接类型为TCP或UDP，则默认使用TCP连接。“hostfwd=…”这个选项在一个命令行中可以多次重复使用。
• guestfwd=[tcp]:server:port-dev，将客户机中访问IP地址为server的port端口的连接转发到宿主机的dev这个字符设备上。“guestfwd=…”这个选项也可以在一个命令行中多次重复使用。

[root@dhcp-12-166 qemuimage]# qemu-system-x86_64 -m 2G -smp 2 -hda RHEL-7.3-20160817.1.qcow2 -enable-kvm -nographic -netdev user,id=mytap,hostfwd=tcp::5022-:22 -device e1000,netdev=mytap

客户机可以通过10.0.2.2访问宿主机
客户机可以访问外网：wget baidu.com
外网机器可以通过连接宿主机的5022端口访问客户机的22端口
```
## 桥接模式
```bash
-netdev tap,id=id[,fd=h][,ifname=name][,script=file][,downscript=dfile][,helper=helper]

-net tap[,vlan=n][,name=name][,fd=h][,ifname=name][,script=file][,downscript=dfile][,helper=helper]

//script、downscript和helper是用来自动创建bridge和tap接口的脚本

qemu-system-x86_64 -m 2G -hda RHEL-7.3-20160817.1.qcow2 -enable-kvm -nographic -vga none -netdev tap,id=mytap,ifname=tap0,script=/etc/qemu-ifupnew,downscript=/etc/qemu-ifdownnew -device e1000,netdev=mytap

qemu-system-i386 linux.img -net nic -net tap

qemu-system-i386 linux.img -net nic -net tap,"helper=/path/to/qemu-bridge-helper"
```
先运行qemu-ifup然后运行start-qemu，root进入系统后，看到eth0网卡没有ip，为其配置ip，宿主机配置的是`192.168.1.1`，为其配置`192.168.1.2`
`ifconfig eth0 192.168.1.2 up`,之后就可以ping通宿主机了。此时qemu可以和宿主机在内网通信，但是不能和外网通信。
如果有需要上外网可以使用以下脚本，经过测试可以访问外网：
```bash
tunctl -t tap0 -u yrl # yrl为主机名
chmod 0666 /dev/net/tun # 将网卡设置为任何人都有权限使用
ifconfig tap0 192.168.1.1 up # 为tap0网卡设置一个IP地址
echo 1 > /proc/sys/net/ipv4/ip_forward # 宿主机需要为虚拟机开启IP数据包转发
iptables -t nat -A POSTROUTING -j MASQUERADE
```
start-qemu不变，此时宿主机配置好了，接下来配置qemu，进入qemu虚拟机后，为eth0配置ip，同上，之后可以访问宿主机，但是不能访问外网，此时添加默认路由到宿主机虚拟网卡tap0，命令`route add default gw 192.168.1.1`,此时可以访问外网，但不能以域名方式访问，因为没有配置DNS，在qemu上输入如下命令添加nameserver：
`echo 'nameserver 8.8.8.8' > /etc/resolv.conf`,此时就可以用`ping baidu.com`来访问外网了。

# qemu和宿主机文件传输
## 宿主机和qemu网络不通
可以挂载ext4镜像`sudo mount -t ext4 ./rootfs.ext4 /tmp/rootfs` 将文件放进去再umount即可。
## 宿主机和qemu网络通
可以使用宿主机开启http服务`python3 -m http.server ` ,在qemu中使用wget 192.168.1.1:8000/text来访问文件。
# gdb调试程序
为什么要用system模式来调试程序呢？很显然这种方式调试更加稳定，在qemu的user模式下调试，pwndbg插件中时出现一些异常报错，vmmap命令显示异常，在qemu的system下调试这种问题就好多了，调试也顺畅多了，虽然堆的命令不支持，但是还勉强是可以看的。
## 网络模式为user模式调试
start-qemu脚本：
```bash
#!/bin/sh
(
BINARIES_DIR="${0%/*}/"
cd ${BINARIES_DIR}

if [ "${1}" = "serial-only" ]; then
    EXTRA_ARGS='-nographic'
else
    EXTRA_ARGS=''
fi

export PATH="/home/yrl/buildroot-2021.02.4/output/host/bin:${PATH}"
exec qemu-system-aarch64 -M virt -cpu cortex-a53 -nographic -smp 1 -kernel Image -append "rootwait root=/dev/vda console=ttyAMA0" -netdev user,id=eth0 -device virtio-net-device,netdev=eth0 -drive file=rootfs.ext4,if=none,format=raw,id=hd0 -device virtio-blk-device,drive=hd0  ${EXTRA_ARGS} -nic user,hostfwd=tcp::3333-:3333,hostfwd=tcp::5555-:5555
)
```
添加了`-nic user,hostfwd=tcp::3333-:3333,hostfwd=tcp::5555-:5555`,`./start_qemu.sh`启动qemu后在里面运行`ncat -vc "gdbserver 0.0.0.0:5555 ./shared" -kl 0.0.0.0 3333`，在qemu外面`nc 127.0.0.1 3333`,此时qemu会运行`gdbserver 0.0.0.0:5555 ./shared`监听5555端口，此时可以在外面使用gdb-multiarch去连接5555端口来调试程序。
这种方法不稳定，不一定都连的上，反正我试了有的nc完3333端口后，qemu里面无反应。但是这种方法还是可行的。
## tap桥接模式调试
这种方式就更加稳定了，在设置好了网络能与宿主机通信，直接按照上述user模式运行`ncat -vc "gdbserver 0.0.0.0:5555 ./shared" -kl 0.0.0.0 3333`之后按照上述操作就行或者是直接运行`./gdbserver attach 0.0.0.0:5555 ./shared`，在外面gdb-mul直接连接即可。
两种方法第一种多了一个`nc 127.0.0.1 3333` 的操作是为了方便收发数据，往3333端口发数据，gdb里就会断在相应的函数里，意思就是我们可以用pwntools里的io模块来连3333端口，然后就像正常的那样收发数据就行。

注意，调试前要将程序以及程序依赖的lib一同拷贝进qemu相应的/lib下，也可以将lib文件夹放到和程序同一目录，然后将动态链接库指定到libc ld所在路径 `export LD_LIBRARY_PATH=/root/lib`
之后就可以在qemu中运行程序啦！

所需的各种架构的gdbserver连接如下：
1. [自己编译的gdbserver](https://github.com/1094093288/IMG/tree/master/IOT/gdbserver)
2. [海特实验室编译的gdbserver](https://pan.baidu.com/s/1_Grqzwyf3NOesbWLp6gBKg) 密码:hfab
3. [gef插件作者编译的gdbserver](https://github.com/hugsy/gdb-static)

其他的rootfs和vmlinux等我编译完后再上传到github，也不知道能不能传👀

**参考**
1. [buildroot构建MIPS64调试环境](https://www.jianshu.com/p/4faf62335180)
2. [mips64调试环境搭建](https://ruan777.github.io/2020/08/25/mips64%E8%B0%83%E8%AF%95%E7%8E%AF%E5%A2%83%E6%90%AD%E5%BB%BA/)
3. [安装qemu-kvm以及配置桥接网络](https://zhou-yuxin.github.io/articles/2018/%E5%AE%89%E8%A3%85qemu-kvm%E4%BB%A5%E5%8F%8A%E9%85%8D%E7%BD%AE%E6%A1%A5%E6%8E%A5%E7%BD%91%E7%BB%9C/index.html)
