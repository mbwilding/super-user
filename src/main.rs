#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types, clippy::upper_case_acronyms)]

mod ffi;
mod util;

use core::ffi::c_void;
use core::mem::zeroed;
use core::ptr::{null, null_mut};

use ffi::*;
use util::{copy_str, copy_wide, trim_nul};

#[unsafe(no_mangle)]
static _fltused: i32 = 0;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { ExitProcess(101) }
}

#[unsafe(no_mangle)]
pub extern "C" fn mainCRTStartup() -> ! {
    let mut arg = [0u16; 512];
    let has_arg = first_arg(&mut arg);

    if !is_elevated() {
        elevate(if has_arg { Some(&arg) } else { None });
        unsafe { ExitProcess(0) }
    }

    let mut cmd = [0u16; 512];
    if has_arg {
        copy_wide(&mut cmd, trim_nul(&arg));
    } else {
        copy_str(&mut cmd, "cmd.exe /k whoami");
    }

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
        // CloseHandle(token) omitted — freed on ExitProcess (see `run`).

        ok && elevation.TokenIsElevated != 0
    }
}

fn elevate(arg: Option<&[u16]>) {
    let mut exe = [0u16; 512];
    unsafe {
        GetModuleFileNameW(null_mut(), exe.as_mut_ptr(), exe.len() as u32);
    }

    let mut verb = [0u16; 8];
    copy_str(&mut verb, "runas");

    let mut params = [0u16; 520];
    let params_ptr = match arg {
        Some(a) => {
            let a = trim_nul(a);
            let mut i = 0usize;
            params[i] = b'"' as u16;
            i += 1;
            for &c in a {
                if i + 2 >= params.len() {
                    break;
                }
                params[i] = c;
                i += 1;
            }
            params[i] = b'"' as u16;
            i += 1;
            params[i] = 0;
            params.as_ptr()
        }
        None => null(),
    };

    unsafe {
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

        let mut desktop = [0u16; 24];
        copy_str(&mut desktop, "winsta0\\default");

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

        // No cleanup on purpose. We call ExitProcess immediately after returning,
        // and Windows frees every open handle and the environment block on process
        // exit. Omitting CloseHandle/DestroyEnvironmentBlock drops two imports,
        // keeping .idata under 1 KB and removing a 512-byte PE block (5,120 -> 4,608).
        // DestroyEnvironmentBlock(env);
        // CloseHandle(pi.hProcess);
        // CloseHandle(pi.hThread);
        // CloseHandle(hdup);
        // CloseHandle(htoken);
        // CloseHandle(hproc);
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

        let mut name = [0u16; 32];
        copy_str(&mut name, "SeDebugPrivilege");

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
        // CloseHandle(token) omitted — freed on ExitProcess (see `run`).
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
                if is_winlogon(&entry) {
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

        // CloseHandle(snapshot) omitted — freed on ExitProcess (see `run`).
        found
    }
}

fn is_winlogon(entry: &PROCESSENTRY32W) -> bool {
    const NAME: &[u8] = b"winlogon.exe";
    let name = trim_nul(&entry.szExeFile);
    if name.len() != NAME.len() {
        return false;
    }
    for i in 0..name.len() {
        let c = name[i];
        if c > 0x7f || (c as u8).to_ascii_lowercase() != NAME[i] {
            return false;
        }
    }
    true
}

fn first_arg(dst: &mut [u16]) -> bool {
    unsafe {
        let mut argc = 0i32;
        let argv = CommandLineToArgvW(GetCommandLineW(), &mut argc);
        if argv.is_null() || argc < 2 {
            return false;
        }
        let arg = *argv.add(1);
        let mut n = 0usize;
        while *arg.add(n) != 0 {
            n += 1;
        }
        copy_wide(dst, core::slice::from_raw_parts(arg, n));
        true
    }
}
