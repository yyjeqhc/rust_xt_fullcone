## 简单使用rust编写xt_fullcone模块

#### 环境：

```shell
虚拟机安装的ubuntu24
git clone https://github.com/torvalds/linux.git --branch v6.14-rc7 --depth 1 v6.14-rc7
进入 v6.14-rc7文件夹
cp /boot/config-$(uname -r) .config
make LLVM=1 oldconfig	#基于现有系统配置进行升级
make LLVM=1 menuconfig	#进入菜单，自行选配置一些内容
#很可能遇见什么错误，到时候注意在log.txt里面搜索错误，然后问AI解决即可。
time make LLVM=1  V=1 2>&1 -j$(nproc) | tee log.txt
编译完成，安装新的内核
make modules_install
make install
reboot，就是新的内核了。

```

```shell
https://git.netfilter.org/iptables --depth 1
默认下载的是1.8.11版本的，无所谓，不影响。
libipt_FULLCONENAT.c
libipt_RCONENAT.c
libipt_PRCONENAT.c
这3个C文件还是复制到iptables的extensions下面，然后
./autogen.sh
./configure
make
make install
然后iptables --version即可
```

```shell
bindings和helper文件夹，对应linux源码下面rust文件夹下面的同名文件夹需要修改的地方。
内核安装成功的话，直接make LLVM=1即可
```

## 注意事项：

```shell
1.本项目来源于https://github.com/Chion82/netfilter-full-cone-nat，在此基础上进行修改测试
2.本项目基本只是从C翻译过来，没有实现原先那么多功能，能做的就是下面这种了。
iptables的几个扩展，就是复制文件，改改字符串。
这几个rs代码，也就是在fullcone.rs基础上进行复制，修改字符串，然后添加判断逻辑

insmod fullcone.ko
iptables -t nat -A POSTROUTING -o tailscale0 -j FULLCONENAT
iptables -t nat -A PREROUTING -i tailscale0 -j FULLCONENAT

iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING
rmmod fullcone

insmod rcone.ko
iptables -t nat -A POSTROUTING -o tailscale0 -j RCONENAT
iptables -t nat -A PREROUTING -i tailscale0 -j RCONENAT

iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING
rmmod rcone

insmod prcone.ko
iptables -t nat -A POSTROUTING -o tailscale0 -j PRCONENAT
iptables -t nat -A PREROUTING -i tailscale0 -j PRCONENAT

iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING
rmmod prcone

3.谨慎加载模块！可能会导致系统死机！！！
如果遇见模块没有生效的情况，请在加载模块的主机上运行 
conntrack -F
```

测试环境：

```shell
ubuntu24主机一台，加载模块，运行容器。
和ubuntu24使用tailscale相连的网络设备多台。
实现容器和网络设备之间的fullcone/rcone/prcone
```



