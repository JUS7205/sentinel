//! Windows process enumeration via the Win32 Toolhelp snapshot API.
//!
//! We use `CreateToolhelp32Snapshot` + `Process32First/Next` — the standard,
//! stable, user-mode way to list processes without admin. This is the same
//! primitive anti-cheat engines use to map a target's process tree.

use crate::process::ProcessInfo;

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::ProcessStatus::{K32EnumProcessModules, K32GetModuleBaseNameA};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

pub(super) fn collect_all() -> Vec<ProcessInfo> {
    let mut out = Vec::new();
    unsafe {
        // CreateToolhelp32Snapshot returns INVALID_HANDLE_VALUE (-1) on failure,
        // not a HANDLE newtype, so we check the raw value.
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == -1 {
            return out;
        }
        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snap, &mut entry) != 0 {
            loop {
                let pid = entry.th32ProcessID;
                let ppid = entry.th32ParentProcessID;
                let name = decode_name(pid);
                out.push(ProcessInfo {
                    pid,
                    parent_pid: ppid,
                    name,
                });
                if Process32Next(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

/// Resolve a process name from its first module. Falls back to a placeholder
/// when module enumeration is unavailable (e.g. access denied on a protected
/// process) — we never panic on a single inaccessible process.
fn decode_name(pid: u32) -> String {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle == 0 || handle == -1 {
            return format!("<pid {}>", pid);
        }
        let mut mods: windows_sys::Win32::Foundation::HANDLE = std::mem::zeroed();
        let mut needed: u32 = 0;
        let mut buf = [0u8; 260];
        if K32EnumProcessModules(
            handle,
            &mut mods,
            std::mem::size_of::<windows_sys::Win32::Foundation::HANDLE>() as u32,
            &mut needed,
        ) != 0
        {
            K32GetModuleBaseNameA(handle, mods, buf.as_mut_ptr(), buf.len() as u32);
        }
        CloseHandle(handle);
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    }
}
