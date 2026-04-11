# ==============================================================================
# 
# Copyright (c) 2026 VISIONGAIATECHNOLOGY
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ==============================================================================



@'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace VGT.Security.XDR {
    public static class Win32TokenXDR {
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public long Luid; public uint Attributes; }
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
    }

    public static class MemoryScanner {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr LoadLibrary(string lpFileName);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FreeLibrary(IntPtr hModule);
        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);
        [DllImport("psapi.dll", CharSet = CharSet.Auto)]
        public static extern uint GetModuleBaseName(IntPtr hProcess, IntPtr hModule, StringBuilder lpBaseName, uint nSize);

        // Constants
        const uint PROCESS_QUERY_INFORMATION = 0x0400;
        const uint PROCESS_VM_READ = 0x0010;
        const uint LIST_MODULES_ALL = 0x03;

        public static long GetAmsiOffset() {
            IntPtr hAmsi = LoadLibrary("amsi.dll");
            if (hAmsi == IntPtr.Zero) return 0;
            try {
                IntPtr pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
                if (pAmsiScanBuffer == IntPtr.Zero) return 0;
                return pAmsiScanBuffer.ToInt64() - hAmsi.ToInt64();
            } finally {
                FreeLibrary(hAmsi); // Platin Status: Zero Handle Leaks
            }
        }

        public static bool IsAmsiPatched(int processId, long amsiOffset) {
            if (amsiOffset == 0) return false;
            
            // Require QueryInformation to enumerate modules cross-architecture via NTAPI
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processId);
            if (hProcess == IntPtr.Zero) return false;

            try {
                IntPtr[] hModules = new IntPtr[1024];
                uint cbNeeded;
                
                // Platin Status: EnumProcessModulesEx bypasses 32/64 bit Process.Modules limitation
                if (!EnumProcessModulesEx(hProcess, hModules, (uint)(IntPtr.Size * hModules.Length), out cbNeeded, LIST_MODULES_ALL)) {
                    return false;
                }

                int numModules = (int)(cbNeeded / IntPtr.Size);
                IntPtr remoteAmsiBase = IntPtr.Zero;
                StringBuilder moduleName = new StringBuilder(1024);

                for (int i = 0; i < numModules; i++) {
                    moduleName.Clear();
                    if (GetModuleBaseName(hProcess, hModules[i], moduleName, (uint)moduleName.Capacity) > 0) {
                        if (moduleName.ToString().Equals("amsi.dll", StringComparison.OrdinalIgnoreCase)) {
                            remoteAmsiBase = hModules[i];
                            break;
                        }
                    }
                }

                if (remoteAmsiBase == IntPtr.Zero) return false;

                IntPtr targetAddress = new IntPtr(remoteAmsiBase.ToInt64() + amsiOffset);
                byte[] buffer = new byte[8];
                IntPtr bytesRead;

                if (ReadProcessMemory(hProcess, targetAddress, buffer, buffer.Length, out bytesRead)) {
                    // Signatur-Erkennung für AMSI Bypasses
                    // B8 57 00 07 80 -> mov eax, 0x80070057 (E_INVALIDARG)
                    if (buffer[0] == 0xB8 && buffer[1] == 0x57 && buffer[2] == 0x00 && buffer[3] == 0x07 && buffer[4] == 0x80) return true;
                    // EB oder E9 -> JMP (Hooking/Redirect)
                    if (buffer[0] == 0xEB || buffer[0] == 0xE9) return true; 
                    // C3 -> RET (Immediate Return)
                    if (buffer[0] == 0xC3) return true; 
                    // 31 C0 C3 -> xor eax, eax; ret (Return Clean)
                    if (buffer[0] == 0x31 && buffer[1] == 0xC0 && buffer[2] == 0xC3) return true; 
                }
                return false;
            }
            catch { return false; } 
            finally { CloseHandle(hProcess); } // Platin Status: Deterministic Resource Release
        }
    }
}
'@
