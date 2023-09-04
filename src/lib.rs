//! # System Tracing Module
//!
//! `System Tracing` crate helps you dynamically trace instructions and functions in both user mode
//! and kernel mode of the operating system via addresses, and allows for custom-designed tracing code.
//!

#![no_std]
#![feature(asm)]
#![feature(naked_functions)]
#![feature(cfg_target_has_atomic)]

#[macro_use]
extern crate log;
extern crate alloc;

mod probes;
mod kprobes;
mod uprobes;

pub use probes::{ProbePlace, ProbeType};
pub use uprobes::{uprobes_trap_handler, uprobe_register,
                  uprobes_init, uprobes_kernel_function_initialization};
pub use kprobes::{kprobes_trap_handler, kprobe_register, kprobe_unregister};

