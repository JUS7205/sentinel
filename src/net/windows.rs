//! Windows IPv4 TCP enumeration via `GetExtendedTcpTable`.
//!
//! `TCP_TABLE_OWNER_PID_ALL` returns every socket with its owning PID — the
//! attribution an anti-cheat or EDR needs to ask "why is this agent holding an
//! outbound connection to an unknown host?"

use super::Connection;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;

pub(super) fn collect_all() -> Vec<Connection> {
    let mut out = Vec::new();
    unsafe {
        // First call sizes the buffer.
        let mut size: u32 = 0;
        let _ = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if size == 0 {
            return out;
        }
        let mut buf: Vec<u8> = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if ret != 0 {
            return out;
        }
        let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
        let count = (*table).dwNumEntries;
        let base = &(*table).table[0] as *const MIB_TCPROW_OWNER_PID;
        for i in 0..count {
            let row = &*base.add(i as usize);
            out.push(Connection {
                pid: row.dwOwningPid,
                local_addr: sock(row.dwLocalAddr, row.dwLocalPort),
                remote_addr: sock(row.dwRemoteAddr, row.dwRemotePort),
                state: tcp_state(row.dwState),
            });
        }
    }
    out
}

/// Format an IPv4 address + port. Address/port arrive in network byte order.
fn sock(addr_be: u32, port_be: u32) -> String {
    let ip = std::net::Ipv4Addr::from(u32::from_be(addr_be));
    let port = u16::from_be(port_be as u16);
    format!("{}:{}", ip, port)
}

/// Map `MIB_TCP_STATE_*` values to names.
fn tcp_state(s: u32) -> String {
    match s {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => return format!("STATE_{}", s),
    }
    .to_string()
}
