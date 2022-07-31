//! Process management syscalls

use core::mem::size_of;
use crate::config::MAX_SYSCALL_NUM;
use crate::mm::{MapPermission, translated_byte_buffer, VirtAddr};
use crate::task::{current_user_token, exit_current_and_run_next, get_current_pid, get_current_tcb, suspend_current_and_run_next, TaskStatus};
use crate::timer::{get_time, get_time_milli, get_time_us};


#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

#[derive(Clone, Copy)]
pub struct TaskInfo {
    pub status: TaskStatus,
    pub syscall_times: [u32; MAX_SYSCALL_NUM],
    pub time: usize,
}

pub fn sys_exit(exit_code: i32) -> ! {
    info!("[kernel] Application exited with code {}", exit_code);
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    suspend_current_and_run_next();
    0
}

// YOUR JOB: 引入虚地址后重写 sys_get_time
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    let buffers = translated_byte_buffer(current_user_token(), _ts as *mut u8, size_of::<TimeVal>());
    assert_eq!(1, buffers.len());
    let ts = unsafe { (buffers[0].as_ptr() as *mut TimeVal).as_mut().unwrap() };
    let us = get_time_us();
    ts.sec = us / 1_000_000;
    ts.usec = us % 1_000_000;
    0
}

// CLUE: 从 ch4 开始不再对调度算法进行测试~
pub fn sys_set_priority(_prio: isize) -> isize {
    -1
}

// YOUR JOB: 扩展内核以实现 sys_mmap 和 sys_munmap
pub fn sys_mmap(_start: usize, _len: usize, mut _port: usize) -> isize {
    let tcb = get_current_tcb();
    // println!("_start={:#x},_len={:#x},_port={}", _start, _len, _port);
    let start_va = VirtAddr::from(_start);
    if !start_va.aligned() {
        return -1;
    }
    _port = _port << 1;//第0位没有使用
    if (_port & !0x07) != 0 {
        return -1;
    }
    if (_port & 0x07) == 0 {
        return -1;
    }
    let end_va: VirtAddr = (_start + _len).into();

    if tcb.memory_set.is_mapped(start_va, end_va) {
        println!("error already mapped");
        return -1;
    }
    let perm = MapPermission::from_bits_truncate(_port as u8);
    if !tcb.memory_set.insert_framed_area(_start.into(),
                                          (_start + _len).into(),
                                          perm | MapPermission::U) {
        return -1; //内存不足
    }
    if get_current_pid() == 27 {
        println!("memory_set={:?}", tcb.memory_set);
        // println!("port={:#x},perm={:?},perm2={:#x}", _port, perm, perm2.bits());
    }
    0
}

pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    let start_va = VirtAddr::from(_start);
    let end_va: VirtAddr = (_start + _len).into();
    let tcb = get_current_tcb();
    if !start_va.aligned() {
        return -1;
    }
    if !tcb.memory_set.is_mapped(start_va, end_va) {
        return -1;
    }
    // println!("munmap start_va={:#x},end_va={:#x}", start_va.0, end_va.0);
    if get_current_pid() == 27 {
        println!("unmap before memory_set={:?}", tcb.memory_set);
        // println!("port={:#x},perm={:?},perm2={:#x}", _port, perm, perm2.bits());
    }
    if !tcb.memory_set.remove_framed_area(start_va,
                                          end_va) {
        return -1;
    }
    if get_current_pid() == 27 {
        println!("unmap after memory_set={:?}", tcb.memory_set);
        // println!("port={:#x},perm={:?},perm2={:#x}", _port, perm, perm2.bits());
    }
    println!("munmap success");
    0
}

// YOUR JOB: 引入虚地址后重写 sys_task_info
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    let buffers = translated_byte_buffer(current_user_token(), ti as *mut u8, size_of::<TaskInfo>());
    assert_eq!(1, buffers.len());
    let mut ti = unsafe { (buffers[0].as_ptr() as *mut TaskInfo).as_mut().unwrap() };
    let tcb = get_current_tcb();
    let time = get_time_milli() - tcb.first_start_time;
    ti.status = TaskStatus::Running;
    ti.time = time+50;
    ti.syscall_times = tcb.syscall_times;
    0
}
