use std::mem;
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::{
    System::{
        JobObjects::*, Threading::*, 
        SystemInformation::*, Diagnostics::Debug::*,
        ProcessStatus::*, Performance::*, Registry::*,
        WindowsProgramming::*
    },
    Foundation::*,
    Security::*,
};

pub struct AntiAnalysis {
    job_handle: HANDLE,
    dummy_thread: HANDLE,
    suspend_count: u32,
    last_tick: u64,
}

impl AntiAnalysis {
    pub fn new() -> Self {
        Self {
            job_handle: 0,
            dummy_thread: 0,
            suspend_count: 128,
            last_tick: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    pub fn detect_sandbox(&self) -> bool {
        unsafe {
            let suspicious_processes = [
                "vboxservice.exe", "vmtoolsd.exe", "vmusrvc.exe",
                "sandboxie.exe", "wireshark.exe", "procmon.exe",
                "ollydbg.exe", "x64dbg.exe", "ida64.exe", "windbg.exe",
                "pestudio.exe", "processhacker.exe", "scylla.exe",
                "dumpcap.exe", "tcpdump.exe", "fiddler.exe",
                "importrec.exe", "lordpe.exe", "petools.exe",
                "regmon.exe", "filemon.exe", "dbgview.exe",
                "immunitydebugger.exe", "reshacker.exe",
            ];

            // Check system uptime and timing attacks
            let mut perf_data: PERFORMANCE_INFORMATION = mem::zeroed();
            if GetPerformanceInfo(&mut perf_data, mem::size_of::<PERFORMANCE_INFORMATION>() as u32) != 0 {
                if perf_data.SystemUpTime < 600 { 
                    return true;
                }
            }

            // Detect timing anomalies that indicate debugging
            let current_tick = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if current_tick - self.last_tick > 5 {
                return true; // Execution took too long, likely being debugged
            }

            // Check memory size and characteristics
            let mut mem_status: MEMORYSTATUSEX = mem::zeroed();
            mem_status.dwLength = mem::size_of::<MEMORYSTATUSEX>() as u32;
            if GlobalMemoryStatusEx(&mut mem_status) != 0 {
                if mem_status.ullTotalPhys < 4 * 1024 * 1024 * 1024 { // Less than 4GB RAM
                    return true;
                }
            }

            // Check CPU characteristics
            let mut sys_info: SYSTEM_INFO = mem::zeroed();
            GetSystemInfo(&mut sys_info);
            if sys_info.dwNumberOfProcessors < 2 || sys_info.dwNumberOfProcessors > 32 {
                return true;
            }

            // Check for VM-specific registry keys
            let mut key_handle: HKEY = 0;
            let vm_keys = [
                "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
                "SYSTEM\\ControlSet001\\Services\\VMTools",
                "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
            ];

            for key in vm_keys.iter() {
                if RegOpenKeyExA(
                    HKEY_LOCAL_MACHINE,
                    key.as_ptr() as *const i8,
                    0,
                    KEY_READ,
                    &mut key_handle,
                ) == 0 {
                    RegCloseKey(key_handle);
                    return true;
                }
            }

            // Enhanced process detection with window title checks
            let mut processes = [0u32; 2048];
            let mut bytes_returned: u32 = 0;
            if EnumProcesses(
                processes.as_mut_ptr(),
                (processes.len() * mem::size_of::<u32>()) as u32,
                &mut bytes_returned
            ) != 0 {
                let count = bytes_returned as usize / mem::size_of::<u32>();
                for pid in &processes[..count] {
                    let process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, *pid);
                    if process != 0 {
                        let mut name = [0u8; 260];
                        let mut window_name = [0u8; 260];
                        
                        if GetProcessImageFileNameA(process, name.as_mut_ptr(), name.len() as u32) > 0 {
                            let proc_name = String::from_utf8_lossy(&name).to_lowercase();
                            
                            // Check process name
                            if suspicious_processes.iter().any(|&s| proc_name.contains(s)) {
                                CloseHandle(process);
                                return true;
                            }

                            // Check window titles for analysis tools
                            if GetWindowTextA(
                                GetTopWindow(0),
                                window_name.as_mut_ptr(),
                                window_name.len() as i32
                            ) > 0 {
                                let window_text = String::from_utf8_lossy(&window_name).to_lowercase();
                                if window_text.contains("debug") || 
                                   window_text.contains("analyze") ||
                                   window_text.contains("trace") {
                                    CloseHandle(process);
                                    return true;
                                }
                            }
                        }
                        CloseHandle(process);
                    }
                }
            }
        }
        false
    }

    pub fn prevent_debugging(&mut self) -> bool {
        unsafe {
            // Create job object with strict memory limits
            self.job_handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if self.job_handle == 0 {
                return false;
            }

            if AssignProcessToJobObject(self.job_handle, GetCurrentProcess()) == 0 {
                CloseHandle(self.job_handle);
                return false;
            }

            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = mem::zeroed();
            limits.ProcessMemoryLimit = 0x1000;
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;

            if SetInformationJobObject(
                self.job_handle,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const _,
                mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0 {
                CloseHandle(self.job_handle);
                return false;
            }

            // Advanced anti-suspend protection with multiple threads
            for _ in 0..3 {
                let thread = CreateThread(
                    std::ptr::null(),
                    0,
                    None,
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                );
                
                if thread != 0 {
                    // Create complex thread suspension patterns
                    for _ in 0..self.suspend_count {
                        SuspendThread(thread);
                        ResumeThread(thread);
                    }
                    CloseHandle(thread);
                }
            }

            self.dummy_thread = CreateThread(
                std::ptr::null(),
                0,
                None,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            );

            DebugActiveProcessStop(GetCurrentProcessId());

            // Check for hardware breakpoints
            let mut context: CONTEXT = mem::zeroed();
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if GetThreadContext(GetCurrentThread(), &mut context) != 0 {
                if context.Dr0 != 0 || context.Dr1 != 0 || 
                   context.Dr2 != 0 || context.Dr3 != 0 {
                    return true;
                }
            }

            // Check for software breakpoints
            let mut buffer = [0u8; 10];
            let base_addr = prevent_debugging as *const () as *const u8;
            if ReadProcessMemory(
                GetCurrentProcess(),
                base_addr as *const _,
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                std::ptr::null_mut(),
            ) != 0 {
                if buffer.contains(&0xCC) { // INT3 instruction
                    return true;
                }
            }

            // Additional anti-debug checks
            let mut debug_port: u64 = 0;
            let mut debug_flags: u32 = 0;
            let mut debug_object: u64 = 0;

            if NtQueryInformationProcess(
                GetCurrentProcess(),
                7, // ProcessDebugPort
                &mut debug_port as *mut _ as *mut _,
                mem::size_of::<u64>() as u32,
                std::ptr::null_mut()
            ) >= 0 && debug_port != 0 {
                return true;
            }

            if NtQueryInformationProcess(
                GetCurrentProcess(),
                31, // ProcessDebugFlags
                &mut debug_flags as *mut _ as *mut _,
                mem::size_of::<u32>() as u32,
                std::ptr::null_mut()
            ) >= 0 && debug_flags == 0 {
                return true;
            }

            if NtQueryInformationProcess(
                GetCurrentProcess(),
                30, // ProcessDebugObjectHandle
                &mut debug_object as *mut _ as *mut _,
                mem::size_of::<u64>() as u32,
                std::ptr::null_mut()
            ) >= 0 && debug_object != 0 {
                return true;
            }
        }
        false
    }

    pub fn prevent_hooks(&self) -> bool {
        unsafe {
            let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
            let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
            
            if ntdll == 0 || kernel32 == 0 {
                return false;
            }

            // Check for hooks in critical system functions
            let critical_functions = [
                ("ntdll.dll", "NtCreateFile"),
                ("ntdll.dll", "NtOpenFile"),
                ("ntdll.dll", "NtReadFile"),
                ("ntdll.dll", "NtWriteFile"),
                ("ntdll.dll", "NtQueryInformationProcess"),
                ("ntdll.dll", "NtQuerySystemInformation"),
                ("ntdll.dll", "NtCreateThread"),
                ("kernel32.dll", "CreateFileW"),
                ("kernel32.dll", "ReadFile"),
                ("kernel32.dll", "WriteFile"),
                ("kernel32.dll", "LoadLibraryA"),
                ("kernel32.dll", "GetProcAddress"),
            ];

            for (module_name, func_name) in critical_functions.iter() {
                let module = if *module_name == "ntdll.dll" { ntdll } else { kernel32 };
                let func_addr = GetProcAddress(module, func_name.as_ptr() as *const i8);
                
                if func_addr != std::ptr::null_mut() {
                    let bytes = std::slice::from_raw_parts(func_addr as *const u8, 32);
                    
                    // Check for various hook patterns
                    if bytes[0] == 0xE9 || // JMP
                       bytes[0] == 0xFF || // indirect JMP/CALL
                       bytes[0] == 0x68 || // PUSH followed by RET (detour)
                       bytes[0] == 0xEB || // Short JMP
                       (bytes[0] == 0x90 && bytes[1] == 0x90) || // NOPs (possible hook setup)
                       (bytes[0] == 0x48 && bytes[1] == 0xB8) || // MOV RAX, imm64 (hook jump table)
                       (bytes[0] == 0x48 && bytes[1] == 0xFF) // JMP [RAX] (IAT hook)
                    {
                        return true;
                    }

                    // Check for suspicious code patterns
                    let mut suspicious_patterns = 0;
                    for window in bytes.windows(2) {
                        if window == [0x90, 0x90] || // Multiple NOPs
                           window == [0xFF, 0x25] || // JMP indirect
                           window == [0xFF, 0x15]    // CALL indirect
                        {
                            suspicious_patterns += 1;
                        }
                    }

                    if suspicious_patterns > 2 {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn cleanup(&self) {
        unsafe {
            if self.job_handle != 0 {
                CloseHandle(self.job_handle);
            }
            if self.dummy_thread != 0 {
                CloseHandle(self.dummy_thread);
            }
        }
    }
}

impl Drop for AntiAnalysis {
    fn drop(&mut self) {
        self.cleanup();
    }
}

pub fn apply_protections(binary: &mut Vec<u8>) -> bool {
    let mut anti_analysis = AntiAnalysis::new();
    
    if anti_analysis.detect_sandbox() {
        return false;
    }

    if anti_analysis.prevent_debugging() {
        return false;
    }

    if anti_analysis.prevent_hooks() {
        return false;
    }

    true
}
