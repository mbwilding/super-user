use core::ffi::c_void;

pub type HANDLE = *mut c_void;

pub const TOKEN_QUERY: u32 = 0x0008;
pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
pub const TOKEN_DUPLICATE: u32 = 0x0002;
pub const TOKEN_ALL_ACCESS: u32 = 0x000F_01FF;
pub const SE_PRIVILEGE_ENABLED: u32 = 0x0002;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
pub const SECURITY_IDENTIFICATION: i32 = 1;
pub const TOKEN_PRIMARY: i32 = 1;
pub const TOKEN_ELEVATION_CLASS: i32 = 20;
pub const LOGON_WITH_PROFILE: u32 = 1;
pub const NORMAL_PRIORITY_CLASS: u32 = 0x0000_0020;
pub const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
pub const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
pub const SW_SHOWNORMAL: i32 = 1;

#[repr(C)]
pub struct LUID {
    pub LowPart: u32,
    pub HighPart: i32,
}

#[repr(C)]
pub struct LUID_AND_ATTRIBUTES {
    pub Luid: LUID,
    pub Attributes: u32,
}

#[repr(C)]
pub struct TOKEN_PRIVILEGES {
    pub PrivilegeCount: u32,
    pub Privileges: [LUID_AND_ATTRIBUTES; 1],
}

#[repr(C)]
pub struct TOKEN_ELEVATION {
    pub TokenIsElevated: u32,
}

#[repr(C)]
pub struct STARTUPINFOW {
    pub cb: u32,
    pub lpReserved: *mut u16,
    pub lpDesktop: *mut u16,
    pub lpTitle: *mut u16,
    pub dwX: u32,
    pub dwY: u32,
    pub dwXSize: u32,
    pub dwYSize: u32,
    pub dwXCountChars: u32,
    pub dwYCountChars: u32,
    pub dwFillAttribute: u32,
    pub dwFlags: u32,
    pub wShowWindow: u16,
    pub cbReserved2: u16,
    pub lpReserved2: *mut u8,
    pub hStdInput: HANDLE,
    pub hStdOutput: HANDLE,
    pub hStdError: HANDLE,
}

#[repr(C)]
pub struct PROCESS_INFORMATION {
    pub hProcess: HANDLE,
    pub hThread: HANDLE,
    pub dwProcessId: u32,
    pub dwThreadId: u32,
}

#[repr(C)]
pub struct PROCESSENTRY32W {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ProcessID: u32,
    pub th32DefaultHeapID: usize,
    pub th32ModuleID: u32,
    pub cntThreads: u32,
    pub th32ParentProcessID: u32,
    pub pcPriClassBase: i32,
    pub dwFlags: u32,
    pub szExeFile: [u16; 260],
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    pub fn GetCurrentProcess() -> HANDLE;
    pub fn OpenProcess(access: u32, inherit: i32, pid: u32) -> HANDLE;
    pub fn ExitProcess(code: u32) -> !;
    pub fn GetCommandLineW() -> *const u16;
    pub fn GetModuleFileNameW(module: HANDLE, filename: *mut u16, size: u32) -> u32;
    pub fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> HANDLE;
    pub fn Process32FirstW(snapshot: HANDLE, entry: *mut PROCESSENTRY32W) -> i32;
    pub fn Process32NextW(snapshot: HANDLE, entry: *mut PROCESSENTRY32W) -> i32;
    pub fn WTSGetActiveConsoleSessionId() -> u32;
    pub fn ProcessIdToSessionId(pid: u32, session: *mut u32) -> i32;
}

#[link(name = "advapi32", kind = "raw-dylib")]
unsafe extern "system" {
    pub fn OpenProcessToken(process: HANDLE, access: u32, token: *mut HANDLE) -> i32;
    pub fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut LUID) -> i32;
    pub fn AdjustTokenPrivileges(
        token: HANDLE,
        disable_all: i32,
        new_state: *const TOKEN_PRIVILEGES,
        len: u32,
        previous: *mut TOKEN_PRIVILEGES,
        ret_len: *mut u32,
    ) -> i32;
    pub fn GetTokenInformation(
        token: HANDLE,
        class: i32,
        info: *mut c_void,
        len: u32,
        ret_len: *mut u32,
    ) -> i32;
    pub fn DuplicateTokenEx(
        token: HANDLE,
        access: u32,
        attrs: *const c_void,
        level: i32,
        token_type: i32,
        new_token: *mut HANDLE,
    ) -> i32;
    pub fn CreateProcessWithTokenW(
        token: HANDLE,
        logon_flags: u32,
        app_name: *const u16,
        cmd_line: *mut u16,
        creation_flags: u32,
        environment: *const c_void,
        current_dir: *const u16,
        startup_info: *const STARTUPINFOW,
        process_info: *mut PROCESS_INFORMATION,
    ) -> i32;
}

#[link(name = "userenv", kind = "raw-dylib")]
unsafe extern "system" {
    pub fn CreateEnvironmentBlock(
        environment: *mut *mut c_void,
        token: HANDLE,
        inherit: i32,
    ) -> i32;
}

#[link(name = "shell32", kind = "raw-dylib")]
unsafe extern "system" {
    pub fn ShellExecuteW(
        hwnd: HANDLE,
        operation: *const u16,
        file: *const u16,
        params: *const u16,
        dir: *const u16,
        show: i32,
    ) -> HANDLE;
}
