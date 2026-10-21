//! Signature scanning, code writes, memory near the image and fault-safe reads.

use std::{ffi::c_void, ptr, slice};

use windows_sys::Win32::System::{
    Diagnostics::Debug::{FlushInstructionCache, ReadProcessMemory},
    Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualProtect},
    Threading::GetCurrentProcess,
};

const SECTION_EXECUTABLE: u32 = 0x2000_0000;

/// The server executable as mapped in this process.
#[derive(Clone, Copy)]
pub struct Image {
    pub base: usize,
    /// PE link timestamp; identifies the build in the log.
    pub timestamp: u32,
}

impl Image {
    /// # Safety
    /// `base` must be the base address of a mapped PE image.
    pub unsafe fn from_base(base: usize) -> Image {
        unsafe {
            let nt = base + read::<u32>(base + 0x3c) as usize;
            Image { base, timestamp: read::<u32>(nt + 8) }
        }
    }

    fn executable_sections(&self) -> Vec<&'static [u8]> {
        unsafe {
            let nt = self.base + read::<u32>(self.base + 0x3c) as usize;
            let count = read::<u16>(nt + 6) as usize;
            let first = nt + 24 + read::<u16>(nt + 20) as usize;
            (0..count)
                .map(|i| first + 40 * i)
                .filter(|&s| read::<u32>(s + 36) & SECTION_EXECUTABLE != 0)
                .map(|s| {
                    let (size, rva) = (read::<u32>(s + 8) as usize, read::<u32>(s + 12) as usize);
                    slice::from_raw_parts((self.base + rva) as *const u8, size)
                })
                .collect()
        }
    }

    /// Every address matching an `AA BB ?? CC` signature in executable sections.
    pub fn find_all(&self, signature: &str) -> Vec<usize> {
        let Some(pattern) = parse_signature(signature) else { return Vec::new() };
        let mut found = Vec::new();
        for section in self.executable_sections() {
            for (offset, window) in section.windows(pattern.len()).enumerate() {
                if matches(&pattern, window) {
                    found.push(section.as_ptr() as usize + offset);
                }
            }
        }
        found
    }

    pub fn rva(&self, address: usize) -> usize {
        address - self.base
    }

    /// `len` bytes from `address` lie inside one executable section of the image.
    pub fn is_code(&self, address: usize, len: usize) -> bool {
        self.executable_sections().iter().any(|s| {
            let start = s.as_ptr() as usize;
            address >= start && address.checked_add(len).is_some_and(|end| end <= start + s.len())
        })
    }
}

pub fn matches(pattern: &[Option<u8>], bytes: &[u8]) -> bool {
    pattern.len() <= bytes.len() && pattern.iter().zip(bytes).all(|(want, have)| want.is_none_or(|b| b == *have))
}

pub fn parse_signature(signature: &str) -> Option<Vec<Option<u8>>> {
    let pattern: Option<Vec<_>> = signature
        .split_whitespace()
        .map(|token| match token {
            "?" | "??" => Some(None),
            _ => u8::from_str_radix(token, 16).ok().map(Some),
        })
        .collect();
    pattern.filter(|p| !p.is_empty())
}

/// # Safety
/// `address` must be readable for `size_of::<T>()` bytes.
pub unsafe fn read<T: Copy>(address: usize) -> T {
    unsafe { ptr::read_unaligned(address as *const T) }
}

/// Reads game memory without risking an access violation: None if any byte is unreadable.
pub fn safe_read(address: usize, len: usize) -> Option<Vec<u8>> {
    if address < 0x10000 {
        return None;
    }
    let mut buffer = vec![0u8; len];
    let mut done = 0usize;
    let ok = unsafe {
        ReadProcessMemory(GetCurrentProcess(), address as *const c_void, buffer.as_mut_ptr().cast(), len, &mut done)
    };
    (ok != 0 && done == len).then_some(buffer)
}

/// Overwrites code at `address`, whatever the page protection.
pub fn write(address: usize, bytes: &[u8]) -> bool {
    unsafe {
        let target = address as *mut c_void;
        let mut old = 0;
        if VirtualProtect(target, bytes.len(), PAGE_EXECUTE_READWRITE, &mut old) == 0 {
            return false;
        }
        ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len());
        VirtualProtect(target, bytes.len(), old, &mut old);
        FlushInstructionCache(GetCurrentProcess(), target, bytes.len());
        true
    }
}

/// Executable memory close enough to `address` for rel32 jumps and rip-relative operands.
pub fn alloc_near(address: usize, size: usize) -> usize {
    const GRANULARITY: usize = 0x1_0000;
    const REACH: usize = 0x7000_0000;
    let start = address & !(GRANULARITY - 1);
    (1..REACH / GRANULARITY)
        .flat_map(|step| [start.checked_sub(step * GRANULARITY), start.checked_add(step * GRANULARITY)])
        .flatten()
        .find_map(|candidate| {
            let memory = unsafe {
                VirtualAlloc(candidate as *const c_void, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            };
            (!memory.is_null()).then_some(memory as usize)
        })
        .unwrap_or(0)
}
