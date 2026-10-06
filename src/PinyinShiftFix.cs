using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Xml.Serialization;
using Microsoft.Win32;

public sealed class BackupRecord
{
    public string OriginalHash, PatchedHash, FileSecurity, UserSid;
    public bool SettingExisted;
    public int SettingValue;
}
internal static class PinyinShiftFix
{
    static PatchPlan Plan;
    static string OriginalHash { get { return Plan.OriginalHash; } }
    static string PatchedHash { get { return Plan.PatchedHash; } }
    static void SelectPlan() {
        byte[] bytes = File.ReadAllBytes(Target); string hash = Hash(bytes);
        if (Directory.Exists(BackupDir)) foreach (string path in Directory.GetFiles(BackupDir, "*.xml")) {
            BackupRecord record;
            try { using (var f = File.OpenRead(path)) record = (BackupRecord)new XmlSerializer(typeof(BackupRecord)).Deserialize(f); }
            catch { continue; }
            if (record.PatchedHash != hash) continue;
            Plan = new PatchPlan { OriginalHash = record.OriginalHash, PatchedHash = record.PatchedHash };
            if (record.OriginalHash == null || record.OriginalHash.Length != 64 ||
                record.OriginalHash.Trim("0123456789ABCDEF".ToCharArray()).Length != 0 ||
                !File.Exists(BackupFile) || HashFile(BackupFile) != record.OriginalHash)
                throw new Exception("已修补文件的原版备份验证失败。");
            return;
        }
        Plan = PatchEngine.Analyze(bytes, null);
    }
    const string SettingKey = @"Software\Microsoft\InputMethod\Settings\CHS";
    const string SettingName = "EnableFullHalfWidthSwitchKey";
    static readonly string Target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "InputService.dll");
    static readonly string BackupDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "PinyinShiftFix");
    static bool Legacy { get { return OriginalHash == "EE32A592C481A01049A618DA1941C6512E5DBA4C326DACA134F9E64472AB0D32" && File.Exists(Path.Combine(BackupDir,"backup.xml")); } }
    static string BackupFile { get { return Path.Combine(BackupDir, Legacy ? "InputService-10.0.19041.2913.original.dll" : OriginalHash + ".original.dll"); } }
    static string RecordFile { get { return Path.Combine(BackupDir, Legacy ? "backup.xml" : OriginalHash + ".xml"); } }
    static readonly StringBuilder Log = new StringBuilder();
    static readonly AccessControlSections SecuritySections = AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group;
    [STAThread] static int Main(string[] args)
    {
        Application.EnableVisualStyles();
        try
        {
            if (args.Length == 0) { Application.Run(new FixWindow()); return 0; }
            if (args[0] == "--install") Install();
            else if (args[0] == "--restore") Restore();
            else if (args[0] == "--inspect") Inspect();
            else if (args[0] == "--analyze" && args.Length >= 3) {
                var bytes = File.ReadAllBytes(args[2]);
                var p = PatchEngine.Analyze(bytes, args.Length > 3 ? args[3] : null);
                Log.AppendLine("OriginalSHA256=" + p.OriginalHash);
                Log.AppendLine("PatchedSHA256=" + p.PatchedHash);
                Log.AppendLine("PointerFileOffset=0x" + p.Offset.ToString("X"));
                if (Hash(bytes) == p.OriginalHash) PatchEngine.Apply(bytes, p);
                Log.AppendLine("ANALYSIS PASSED; no system or sample files modified.");
            }
            else throw new ArgumentException("Supported commands: --install, --restore, --inspect, --analyze report input [pdb]");
            if (args.Length > 1) File.WriteAllText(args[1], Log.ToString(), Encoding.UTF8);
            return 0;
        }
        catch (Exception ex)
        {
            Log.AppendLine("ERROR: " + ex);
            if (args.Length > 1) File.WriteAllText(args[1], Log.ToString(), Encoding.UTF8);
            else MessageBox.Show(ex.Message, "微软拼音修复失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
    static string Hash(byte[] bytes) { using (var s = SHA256.Create()) return BitConverter.ToString(s.ComputeHash(bytes)).Replace("-", ""); }
    static string HashFile(string path) { return Hash(File.ReadAllBytes(path)); }
    static void Inspect()
    {
        Log.AppendLine("Target=" + Target);
        Log.AppendLine("Version=" + FileVersionInfo.GetVersionInfo(Target).FileVersion);
        Log.AppendLine("SHA256=" + HashFile(Target));
        Log.AppendLine("State=" + State());
    }
    static string State()
    {
        SelectPlan();
        string h = HashFile(Target);
        return h == OriginalHash ? "受支持的原版，尚未修补" : h == PatchedHash ? "文件补丁已安装" : "版本不匹配，拒绝修改";
    }
    static void RequireAdmin()
    {
        if (!Environment.Is64BitProcess || !Environment.Is64BitOperatingSystem) throw new Exception("此补丁只支持本次验证的 64 位 Windows 10 组件。");
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) throw new Exception("需要 Windows 管理员权限。");
        EnablePrivilege("SeTakeOwnershipPrivilege"); EnablePrivilege("SeRestorePrivilege");
    }
    static void PrepareBackupDirectory()
    {
        Directory.CreateDirectory(BackupDir);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { WellKnownSidType.BuiltinAdministratorsSid, WellKnownSidType.LocalSystemSid })
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        Directory.SetAccessControl(BackupDir, security);
    }
    static BackupRecord ReadRecord()
    {
        using (var f = File.OpenRead(RecordFile)) return (BackupRecord)new XmlSerializer(typeof(BackupRecord)).Deserialize(f);
    }
    static BackupRecord EnsureBackup()
    {
        PrepareBackupDirectory();
        if (File.Exists(RecordFile))
        {
            var existing = ReadRecord();
            if (existing.OriginalHash != OriginalHash || existing.PatchedHash != PatchedHash || HashFile(BackupFile) != OriginalHash)
                throw new Exception("备份校验失败，未修改系统文件。");
            return existing;
        }
        if (File.Exists(BackupFile) && HashFile(BackupFile) != OriginalHash) throw new Exception("已有备份与目标版本不一致。");
        File.Copy(Target, BackupFile, true);
        if (HashFile(BackupFile) != OriginalHash) throw new Exception("原始文件备份校验失败。");
        var record = new BackupRecord {
            OriginalHash = OriginalHash, PatchedHash = PatchedHash,
            FileSecurity = File.GetAccessControl(Target, SecuritySections).GetSecurityDescriptorSddlForm(SecuritySections),
            UserSid = WindowsIdentity.GetCurrent().User.Value
        };
        using (var key = Registry.CurrentUser.OpenSubKey(SettingKey))
        {
            var value = key == null ? null : key.GetValue(SettingName);
            record.SettingExisted = value != null;
            if (value != null)
            {
                if (!(value is int)) throw new Exception("输入法设置类型异常，未修改。");
                record.SettingValue = (int)value;
            }
        }
        using (var f = File.Create(RecordFile)) new XmlSerializer(typeof(BackupRecord)).Serialize(f, record);
        return record;
    }
    static byte[] PatchedBytes()
    {
        return PatchEngine.Apply(File.ReadAllBytes(BackupFile), Plan);
    }
    static void ApplySecurity(string path, string sddl)
    {
        var security = new FileSecurity();
        security.SetSecurityDescriptorSddlForm(sddl, SecuritySections);
        File.SetAccessControl(path, security);
    }
    static void AllowReplacement(string path)
    {
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var owner = new FileSecurity(); owner.SetOwner(admins); File.SetAccessControl(path, owner);
        var acl = File.GetAccessControl(path);
        acl.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, AccessControlType.Allow));
        File.SetAccessControl(path, acl);
    }
    static void ReplaceFile(byte[] bytes, string expectedCurrentHash, string finalHash, string sddl)
    {
        if (HashFile(Target) != expectedCurrentHash) throw new Exception("系统文件已经变化，取消写入。");
        string token = Guid.NewGuid().ToString("N");
        string prepared = Target + ".pinyinfix-new-" + token;
        string parked = Target + ".pinyinfix-old-" + token;
        bool moved = false, installed = false;
        try
        {
            File.WriteAllBytes(prepared, bytes);
            if (HashFile(prepared) != finalHash) throw new Exception("写入前校验失败。");
            AllowReplacement(Target);
            File.Move(Target, parked); moved = true;
            File.Move(prepared, Target); installed = true;
            ApplySecurity(Target, sddl);
            ApplySecurity(parked, sddl);
            if (HashFile(Target) != finalHash) throw new Exception("写入后校验失败。");
            Log.AppendLine("Replaced and verified " + Target);
            // The old loaded image can remain mapped until the input service restarts.
            try { AllowReplacement(parked); File.Delete(parked); }
            catch { ApplySecurity(parked, sddl); Log.AppendLine("Old mapped file retained: " + parked); }
        }
        catch
        {
            if (moved && File.Exists(parked))
            {
                if (installed && File.Exists(Target)) { AllowReplacement(Target); File.Delete(Target); }
                AllowReplacement(parked); File.Move(parked, Target); ApplySecurity(Target, sddl);
                Log.AppendLine("File replacement rolled back.");
            }
            else if (!moved && File.Exists(Target)) ApplySecurity(Target, sddl);
            throw;
        }
        finally { if (File.Exists(prepared)) File.Delete(prepared); }
    }
    static void SetDisabled()
    {
        using (var key = Registry.CurrentUser.CreateSubKey(SettingKey)) key.SetValue(SettingName, 0, RegistryValueKind.DWord);
    }
    static void RestoreSetting(BackupRecord record)
    {
        if (record.UserSid != WindowsIdentity.GetCurrent().User.Value) { Log.AppendLine("Setting belongs to another user; left unchanged."); return; }
        using (var key = Registry.CurrentUser.CreateSubKey(SettingKey))
        {
            if (!Object.Equals(key.GetValue(SettingName), 0)) { Log.AppendLine("User has changed the setting; left unchanged."); return; }
            if (record.SettingExisted) key.SetValue(SettingName, record.SettingValue, RegistryValueKind.DWord);
            else key.DeleteValue(SettingName, false);
        }
    }
    static void Install()
    {
        RequireAdmin(); Inspect();
        string current = HashFile(Target);
        if (current == PatchedHash) { CleanupParked(); Log.AppendLine("Already installed. No further changes."); return; }
        if (current != OriginalHash) throw new Exception("文件与分析结果不一致，取消修改。");
        var record = EnsureBackup(); byte[] patched = PatchedBytes();
        ReplaceFile(patched, OriginalHash, PatchedHash, record.FileSecurity);
        try { SetDisabled(); RestartInputService(); }
        catch
        {
            ReplaceFile(File.ReadAllBytes(BackupFile), PatchedHash, OriginalHash, record.FileSecurity);
            RestoreSetting(record); RestartInputService(); throw;
        }
        CleanupParked(); Log.AppendLine("INSTALLED: persistent file patch; no resident helper or startup task.");
    }
    static void Restore()
    {
        RequireAdmin(); Inspect();
        if (HashFile(Target) == OriginalHash) { Log.AppendLine("Original system file already present."); return; }
        if (HashFile(Target) != PatchedHash) throw new Exception("系统文件已被更新或另行修改，拒绝用旧版本覆盖。");
        var record = ReadRecord();
        if (record.OriginalHash != OriginalHash || record.PatchedHash != PatchedHash || HashFile(BackupFile) != OriginalHash) throw new Exception("原版备份验证失败。");
        ReplaceFile(File.ReadAllBytes(BackupFile), PatchedHash, OriginalHash, record.FileSecurity);
        RestoreSetting(record); RestartInputService(); CleanupParked(); Log.AppendLine("RESTORED original file and applicable setting.");
    }
    static void CleanupParked()
    {
        foreach (string path in Directory.GetFiles(Path.GetDirectoryName(Target), Path.GetFileName(Target) + ".pinyinfix-old-*"))
        {
            if (!Path.GetFullPath(path).StartsWith(Target + ".pinyinfix-old-", StringComparison.OrdinalIgnoreCase)) continue;
            string hash = HashFile(path);
            if (hash != OriginalHash && hash != PatchedHash) continue;
            string sddl = File.GetAccessControl(path, SecuritySections).GetSecurityDescriptorSddlForm(SecuritySections);
            try { AllowReplacement(path); File.Delete(path); Log.AppendLine("Cleaned replaced image: " + Path.GetFileName(path)); }
            catch { if (File.Exists(path)) ApplySecurity(path, sddl); Log.AppendLine("Mapped old image remains until released: " + Path.GetFileName(path)); }
        }
    }
    static void RestartInputService()
    {
        int session = Process.GetCurrentProcess().SessionId;
        foreach (var p in Process.GetProcessesByName("ctfmon"))
            using (p) if (p.SessionId == session) { p.Kill(); if (!p.WaitForExit(5000)) throw new Exception("输入服务未能退出。"); }
        Thread.Sleep(500);
        foreach (var p in Process.GetProcessesByName("ctfmon")) using (p) if (p.SessionId == session) return;
        using (var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "ctfmon.exe"))
            { UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden }))
        { Thread.Sleep(800); if (p.HasExited && p.ExitCode != 0) throw new Exception("输入服务启动失败。"); }
        Log.AppendLine("Input service restarted. Existing IME composition is cleared.");
    }
    [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] struct TokenPrivileges { public uint Count; public Luid Luid; public uint Attributes; }
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr token);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeValue(string system, string name, out Luid luid);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disable, ref TokenPrivileges privileges, uint length, IntPtr old, IntPtr size);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    static void EnablePrivilege(string name)
    {
        IntPtr token;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x20 | 8, out token)) throw new System.ComponentModel.Win32Exception();
        try
        {
            Luid luid; if (!LookupPrivilegeValue(null, name, out luid)) throw new System.ComponentModel.Win32Exception();
            var privileges = new TokenPrivileges { Count = 1, Luid = luid, Attributes = 2 };
            if (!AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastWin32Error() != 0)
                throw new System.ComponentModel.Win32Exception();
        }
        finally { CloseHandle(token); }
    }
    sealed class FixWindow : Form
    {
        readonly TextBox output = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill };
        internal FixWindow()
        {
            Text = "微软拼音 Shift 自动全角修复补丁"; Width = 750; Height = 440;
            var description = new Label { Dock = DockStyle.Top, Height = 110, Padding = new Padding(12), Text =
                "1.已测试Windows 10 x64 2913 6456 新版本首次识别需要联网。\r\n2.安装或还原会重启输入服务，执行过程中请不要使用输入法输入文字。 \r\n3.若提示版本不匹配，可借助AGENTS.md使用AI工具开发专用版本" };
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 50 };
            foreach (bool restore in new[] { false, true })
            {
                bool undo = restore;
                var button = new Button { Text = undo ? "从备份还原" : "安装补丁", Width = 180, Height = 34 };
                button.Click += delegate
                {
                    buttons.Enabled = false; Log.Clear();
                    try { if (undo) Restore(); else Install(); output.Text = Log.ToString(); }
                    catch (Exception ex) { output.Text = Log + "\r\n操作失败：" + ex.Message; }
                    finally { buttons.Enabled = true; }
                };
                buttons.Controls.Add(button);
            }
            Controls.Add(output); Controls.Add(buttons); Controls.Add(description);
            output.Text = "点击安装将分析当前组件并建立备份。\r\n备份位置：" + BackupDir;
        }
    }
}

