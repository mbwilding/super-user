#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types, clippy::upper_case_acronyms)]

mod ffi;
mod util;

use core::ffi::c_void;
use core::mem::zeroed;
use core::ptr::{null, null_mut};

use ffi::*;
use util::{copy_wide, eq_ignore_case_ascii, trim_nul};

#[unsafe(no_mangle)]
static _fltused: i32 = 0;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { ExitProcess(101) }
}

#[unsafe(no_mangle)]
pub extern "C" fn mainCRTStartup() -> ! {
    let tail = cmd_tail();

    if !is_elevated() {
        elevate(tail);
        unsafe { ExitProcess(0) }
    }

    let mut cmd = [0u16; 512];
    let default = wstr!("cmd.exe /k whoami");
    copy_wide(&mut cmd, if tail.is_empty() { &default } else { tail });

    run(&mut cmd);
    unsafe { ExitProcess(0) }
}

fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TOKEN_ELEVATION_CLASS,
            &mut elevation as *mut _ as *mut c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        ) != 0;

        ok && elevation.TokenIsElevated != 0
    }
}

fn elevate(params: &[u16]) {
    let mut exe = [0u16; 512];
    unsafe {
        GetModuleFileNameW(null_mut(), exe.as_mut_ptr(), exe.len() as u32);

        let verb = wstr!("runas");
        let params_ptr = if params.is_empty() {
            null()
        } else {
            params.as_ptr()
        };

        ShellExecuteW(
            null_mut(),
            verb.as_ptr(),
            exe.as_ptr(),
            params_ptr,
            null(),
            SW_SHOWNORMAL,
        );
    }
}

fn run(cmd: &mut [u16]) {
    enable_privilege();

    let Some(pid) = find_winlogon() else {
        return;
    };

    unsafe {
        let hproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if hproc.is_null() {
            return;
        }

        let mut htoken: HANDLE = null_mut();
        if OpenProcessToken(hproc, TOKEN_DUPLICATE | TOKEN_QUERY, &mut htoken) == 0 {
            return;
        }

        let mut hdup: HANDLE = null_mut();
        if DuplicateTokenEx(
            htoken,
            TOKEN_ALL_ACCESS,
            null(),
            SECURITY_IDENTIFICATION,
            TOKEN_PRIMARY,
            &mut hdup,
        ) == 0
        {
            return;
        }

        let mut env: *mut c_void = null_mut();
        CreateEnvironmentBlock(&mut env, htoken, 0);

        let mut desktop = wstr!("winsta0\\default");

        let mut si: STARTUPINFOW = zeroed();
        si.cb = size_of::<STARTUPINFOW>() as u32;
        si.lpDesktop = desktop.as_mut_ptr();

        let mut pi: PROCESS_INFORMATION = zeroed();

        CreateProcessWithTokenW(
            hdup,
            LOGON_WITH_PROFILE,
            null(),
            cmd.as_mut_ptr(),
            NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
            env,
            null(),
            &si,
            &mut pi,
        );
    }
}

fn enable_privilege() {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return;
        }

        let name = wstr!("SeDebugPrivilege");

        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        if LookupPrivilegeValueW(null(), name.as_ptr(), &mut luid) != 0 {
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            AdjustTokenPrivileges(
                token,
                0,
                &tp,
                size_of::<TOKEN_PRIVILEGES>() as u32,
                null_mut(),
                null_mut(),
            );
        }
    }
}

fn find_winlogon() -> Option<u32> {
    unsafe {
        let session = WTSGetActiveConsoleSessionId();
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot as isize == -1 {
            return None;
        }

        let mut entry: PROCESSENTRY32W = zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        let mut found = None;
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                if eq_ignore_case_ascii(trim_nul(&entry.szExeFile), b"winlogon.exe") {
                    let mut sid = 0u32;
                    if ProcessIdToSessionId(entry.th32ProcessID, &mut sid) != 0 && sid == session {
                        found = Some(entry.th32ProcessID);
                        break;
                    }
                }
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        found
    }
}

fn cmd_tail() -> &'static [u16] {
    const SPACE: u16 = b' ' as u16;
    const QUOTE: u16 = b'"' as u16;
    unsafe {
        let p = GetCommandLineW();
        let mut i = 0isize;
        let mut quoted = false;
        loop {
            let c = *p.offset(i);
            if c == 0 {
                return &[];
            }
            if c == QUOTE {
                quoted = !quoted;
            } else if c == SPACE && !quoted {
                break;
            }
            i += 1;
        }
        while *p.offset(i) == SPACE {
            i += 1;
        }
        let start = p.offset(i);
        let mut n = 0isize;
        while *start.offset(n) != 0 {
            n += 1;
        }
        core::slice::from_raw_parts(start, n as usize)
    }
}
