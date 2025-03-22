// SPDX-License-Identifier: GPL-2.0

//! Rust minimal sample.

use core::ffi;
use kernel::prelude::*;
use kernel::sync::{Arc,new_mutex, Mutex};
use kernel::alloc::flags;
use kernel::bindings::{self, *};
use core::ptr;
use core::net::Ipv4Addr;
use kernel::container_of;

module! {
    type: FullConeNatTarget,
    name: "FULLCONENAT",
    author: "yyjeqhc",
    description: "Full Cone NAT target in Rust",
    license: "GPL",
}

// 定义存储NAT映射的结构体
#[derive(Debug)]
struct NatMapping {
    int_addr: u32,          // 内部地址
    int_port: u16,          // 内部端口
    map_ip: u32,
    map_port: u16,
    ext_addr: u32,          // 外部地址
    ext_port: u16,          // 外部端口
    // interface: u8,              // 网络接口
}


static mut mappings: KVec<NatMapping> = KVec::new();
#[derive(Debug)]
struct FullConeNatTarget {
    // mappings: KVec<NatMapping>,  // NAT映射表
    target:u64,            // target结构体
}

impl kernel::Module for FullConeNatTarget {
    fn init(module: &'static ThisModule) -> Result<Self> {
        // pr_info!("FullConeNat: module being initialized\n");
        
        let mut target = KBox::new(xt_target::default(),flags::GFP_KERNEL)?;
        
        // 设置target属性
        let name = b"FULLCONENAT";
        target.name[..name.len()].copy_from_slice(name);
        target.revision = 0;
        target.family = NFPROTO_IPV4 as u16;
        target.table = "nat\0".as_ptr() as *const u8;
        target.hooks = (1 << nf_inet_hooks_NF_INET_PRE_ROUTING) | (1 << nf_inet_hooks_NF_INET_POST_ROUTING);
        target.targetsize = core::mem::size_of::<nf_nat_ipv4_multi_range_compat>() as u32;
        // target.me = module as *const _ as *mut _;
        target.me = unsafe {&mut __this_module as *mut _};
        
        // pr_info!("why {:X}\n",target.me as u64);
        // pr_info!("what's this {:X}\n",module as *const _ as u64);
        // 设置回调函数
        target.target = Some(fullconenat_tg);
        target.checkentry = Some(fullconenat_tg_check); 
        target.destroy = Some(fullconenat_tg_destroy);

        // 注册target

        let target  = KBox::into_raw(target);
        let result = unsafe { bindings::xt_register_targets(target, 1) };
        if result != 0 {
            return Err(kernel::error::Error::from_errno(result));
        }
        // pr_info!("{}\n",core::mem::size_of::<*mut xt_target>());
        pr_info!("FullConeNat: module initialized success\n");
        
        let full = FullConeNatTarget {
            // mappings: KVec::new(),
            target: target  as u64,
        };
        // pr_info!("init {:X}\n",&full as *const _ as u64);
        Ok(full)
    }
}


impl Drop for FullConeNatTarget {
    fn drop(&mut self) {
        pr_info!("FullConeNat: module being removed\n");
        // pr_info!("is ok {}",is_valid_xt_target(self.target));
        // pr_info!("{:X}\n",self.target);
        
        if false {
            unsafe {
                let target = self.target as *const xt_target;
                pr_info!("target addr: {:X}\n", self.target);
            
                if target.is_null() {
                    pr_info!("Null pointer\n");
                    return;
                }
            
                // 将 name 转换为 CStr 并打印
                let name = core::ffi::CStr::from_ptr((*target).name.as_ptr() as *const i8);
                match name.to_str() {
                    Ok(s) => pr_info!("name: {}\n", s),
                    Err(_) => pr_info!("Invalid name at {:X}\n", self.target),
                }
            }
        }
        // let mut target = xt_target::default();
        // let name = b"FULLCONENAT";
        // target.name[..name.len()].copy_from_slice(name);
        
        unsafe { 
            let target_ptr = self.target as *mut xt_target;
            // let module_ptr: *mut FullConeNatTarget = (*(self.target as *mut xt_target)).me as *mut FullConeNatTarget;
            // pr_info!("module {:X}\n",module_ptr as u64);
            bindings::xt_unregister_targets(target_ptr, 1);

            // 恢复 KBox 并释放内存
            let _target = KBox::from_raw(target_ptr); // 自动 Drop
            // pr_info!("lens {}\n",self.mappings.len());
            // pr_info!("self {:X}\n",self as *const _ as u64);
         }
         
        // pr_info!("byebye!\n");
    }
}

fn is_valid_xt_target(addr: u64) -> i32 {
    if addr < 0xFFFF_8000_0000_0000 {
        return 0; // 地址在用户空间，肯定不是 xt_target
    }

    let ptr = addr as *const xt_target;
    
    // 尝试访问 `name` 字段，看是否引发异常
    unsafe {
        let name_ptr = ptr::addr_of!((*ptr).name);
        if name_ptr.is_null() {
            return 1;
        }
        pr_info!("enter the unsafe");
        let first_byte = ptr::read_volatile(name_ptr as *const u8);
        if first_byte == 0 {
            return 2;
        }
    }
    
    3
}


fn get_device_ip(device: &net_device) -> u32 {
    unsafe {
        __rcu_read_lock();
        let in_dev = device.ip_ptr;
        let if_info = (*in_dev).ifa_list;
        let ip = (*if_info).ifa_local;
        __rcu_read_unlock();
        pr_info!("ip {}",Ipv4Addr::from_bits(ip.to_be()));
        ip
    }
}

fn get_proper_port(src_port: u16) -> u16 {
    if src_port == 0 {
        1024_u16.to_be()
    } else {
        src_port.to_be()
    }

}
// target处理函数
extern "C" fn fullconenat_tg(skb: *mut sk_buff, par: *const xt_action_param) -> u32 {

    let mut ret = XT_CONTINUE;
    let hook_type:nf_inet_hooks = unsafe {xt_hooknum(par)};
    let mut ctinfo:u32 = 0;
    let mut ct: *mut nf_conn = unsafe {nf_ct_get(skb,&mut ctinfo)};

    let mut ct_tuple_origin:nf_conntrack_tuple = unsafe {(*ct).tuplehash[ip_conntrack_dir_IP_CT_DIR_ORIGINAL as usize].tuple};
    let protonum = ct_tuple_origin.dst.protonum as u32;
    let mut new_range = nf_nat_range2::default();

    let mr = unsafe {(*par).__bindgen_anon_2.targinfo as *const nf_nat_ipv4_multi_range_compat};

    unsafe {
        new_range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
        new_range.min_proto = (*mr).range[0].min;
        new_range.max_proto = new_range.min_proto;
    }
    match protonum {
        IPPROTO_UDP => {
            pr_info!("FullConeNat: UDP\n");
        }
        _ => {
            return ret;
        }
    }
    pr_info!("hook_type = {}\n",hook_type);
    match hook_type {
        nf_inet_hooks_NF_INET_PRE_ROUTING => {
            let src_ip = unsafe {ct_tuple_origin.src.u3.ip}.to_be();
            let src_port = unsafe {ct_tuple_origin.src.u.udp.port}.to_be();
            let dst_ip = unsafe {ct_tuple_origin.dst.u3.ip}.to_be();
            let dst_port = unsafe {ct_tuple_origin.dst.u.udp.port}.to_be();

            unsafe {
                let mut flag = false;
                pr_info!("len = {}\n",mappings.len());
                pr_info!("{:?}\n",mappings);
                for i in 0..mappings.len() {
                    if mappings[i].map_ip == dst_ip && mappings[i].map_port == dst_port {
                        flag = true;
                        pr_info!("find {}:{}\n",Ipv4Addr::from_bits(dst_ip),dst_port);

                        let map_ip = mappings[i].int_addr.to_be();
                        let map_port = mappings[i].int_port.to_be();
                        new_range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
                        new_range.min_addr.ip = map_ip; 
                        new_range.max_addr.ip = map_ip;
                        new_range.min_proto.udp.port = map_port;
                        new_range.max_proto = new_range.min_proto;
                        ret = nf_nat_setup_info(ct, &new_range, (HOOK2MANIP(xt_hooknum(par))) as i32);
                        pr_info!("FullConeNat: pre_routing from {}:{} to {}:{}\n",Ipv4Addr::from_bits(src_ip),src_port,Ipv4Addr::from_bits(dst_ip),dst_port);

                        return ret;
                    }
                }
                if !flag {
                    return ret;
                }

            }
            
        }
        nf_inet_hooks_NF_INET_POST_ROUTING => {
            let src_ip = unsafe {ct_tuple_origin.src.u3.ip}.to_be();
            let src_port = unsafe {ct_tuple_origin.src.u.udp.port}.to_be();
            let dst_ip = unsafe {ct_tuple_origin.dst.u3.ip}.to_be();
            let dst_port = unsafe {ct_tuple_origin.dst.u.udp.port}.to_be();
            let map_ip = unsafe {
                get_device_ip(&*(*skb).__bindgen_anon_1.__bindgen_anon_1.__bindgen_anon_1.dev)
            };
            // pr_info!("src_port {}\n",src_port);
            let map_port = get_proper_port(src_port);
            // pr_info!("map_port {}\n",map_port);
            //设置newrange
            {
                new_range.min_addr.ip = map_ip;
                new_range.max_addr.ip = map_ip;
                new_range.min_proto.udp.port = map_port;
                new_range.max_proto = new_range.min_proto;
                pr_info!("ip:port {}:{}\n",Ipv4Addr::from_bits(map_ip),map_port);
            }
            unsafe {
                let map = NatMapping {
                    int_addr: src_ip,
                    int_port: src_port,
                    map_ip: map_ip.to_be(), //本来就是be，转换为主机序列
                    map_port: map_port.to_be(),
                    ext_addr: dst_ip,
                    ext_port: dst_port,
                };
                if mappings.len() == 0 {
                    mappings.push(map,flags::GFP_KERNEL);
                } else {
                    let mut flag = false;
                    for i in 0..mappings.len() {
                        if mappings[i].int_addr == src_ip && mappings[i].int_port == src_port {
                            flag = true;
                            break;
                        }
                    }
                    if !flag {
                        mappings.push(map,flags::GFP_KERNEL);
                    }
                }
            }
            pr_info!("FullConeNat: post_routing from {}:{} to {}:{}\n",Ipv4Addr::from_bits(src_ip),src_port,Ipv4Addr::from_bits(dst_ip),dst_port);
            ret = unsafe {nf_nat_setup_info(ct,&new_range, (HOOK2MANIP(xt_hooknum(par))) as i32)};
            pr_info!("ret is {}\n",ret as u32);
            return ret;
        }
        _ => {
            pr_info!("FullConeNat: unknown hook type\n");
        }
    }
    ret
}

// 规则检查函数
extern "C" fn fullconenat_tg_check(par: *const xt_tgchk_param) -> i32 {
    // pr_info!("FullConeNat: checking new rule");
    unsafe {
        let target = (*par).target; // 获取 xt_target 指针

        // if target.is_null() {
        //     pr_err!("FullConeNat: target is null!\n");
        //     return -1;
        // }
        // pr_info!("check {:X}\n",target as u64);
        // pr_info!("{:X}\n",(*target).me as u64);
        // 使用 container_of 获取 `FullConeNatTarget` 实例

        // let module_ptr: *mut FullConeNatTarget = (*target).me as *mut FullConeNatTarget;
        // let module = &mut *module_ptr; // 解除引用
        // module.mappings.push(NatMapping {
        //     int_addr: 0,
        //     int_port: 0,
        //     ext_addr: 0,
        //     ext_port: 0,
        //     interface: 0,
        // },flags::GFP_KERNEL);
        // pr_info!("FullConeNat: Successfully accessed FullConeNatTarget {:X} num {}\n",module.target,module.mappings.len());

        // 你可以在这里使用 `module.mappings` 或其他字段
    }
    // pr_info!("{}",__this_module.target);
    0
}

// 销毁函数
extern "C" fn fullconenat_tg_destroy(par: *const xt_tgdtor_param) {
    // pr_info!("FullConeNat: destroying rule");
}

// fn aa() {
//     let a = 5;
//     a = 666;
// }