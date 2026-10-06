using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;
using PinyinShiftFixTests;
class TriggerLab : Form {
 [StructLayout(LayoutKind.Sequential)] struct INPUT { public uint type; public INPUTUNION data; }
 [StructLayout(LayoutKind.Explicit)] struct INPUTUNION { [FieldOffset(0)] public KEYBDINPUT key; [FieldOffset(0)] public MOUSEINPUT mouse; }
 [StructLayout(LayoutKind.Sequential)] struct KEYBDINPUT { public ushort vk,scan;public uint flags,time;public UIntPtr extra; }
 [StructLayout(LayoutKind.Sequential)] struct MOUSEINPUT {public int x,y;public uint data,flags,time;public UIntPtr extra;}
 [DllImport("user32.dll",SetLastError=true)] static extern uint SendInput(uint n,INPUT[] inputs,int size);
 [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr w,int cmd);
 [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr w);
 [DllImport("imm32.dll",SetLastError=true)] static extern bool ImmGetHotKey(uint id,out uint mod,out uint key,out IntPtr layout);
 [DllImport("imm32.dll",SetLastError=true)] static extern bool ImmSetHotKey(uint id,uint mod,uint key,IntPtr layout);
 TextBox edit = new TextBox{Multiline=true,Dock=DockStyle.Fill,ImeMode=ImeMode.NoControl};
 Timer timer=new Timer{Interval=45};
 StringBuilder log=new StringBuilder(); Queue<Action> steps=new Queue<Action>();
 string path; uint oldMod,oldKey;IntPtr oldLayout;bool restore;int baseline;
 static string Setting=@"Software\Microsoft\InputMethod\Settings\CHS";
 [STAThread] static void Main(string[] args){Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);using(var f=new TriggerLab(args[0])) Application.Run(f);}
 TriggerLab(string output){path=output;Text="Microsoft Pinyin input regression (this window only)";Size=new Size(660,300);Controls.Add(edit);
  log.AppendLine("Original hotkey="+ImmGetHotKey(0x11,out oldMod,out oldKey,out oldLayout)+" modifiers="+oldMod.ToString("X")+" key="+oldKey.ToString("X"));
  Shown+=delegate{ShowWindow(Handle,5);SetForegroundWindow(Handle);Activate();edit.Focus();Build();timer.Start();};
  timer.Tick+=delegate{try {if(steps.Count==0){timer.Stop();Close();return;}steps.Dequeue()();File.WriteAllText(path,log.ToString(),Encoding.UTF8);}catch(Exception ex){log.AppendLine("ERROR "+ex);Close();}};
  FormClosed+=delegate{if(restore)ImmSetHotKey(0x11,oldMod,oldKey,oldLayout);File.WriteAllText(path,log.ToString(),Encoding.UTF8);};
 }
 void Key(int vk,bool up){uint pid;NativeIme.GetWindowThreadProcessId(NativeIme.GetForegroundWindow(),out pid);if(pid!=(uint)System.Diagnostics.Process.GetCurrentProcess().Id)throw new Exception("Test lost foreground; refusing to inject keys elsewhere");var input=new INPUT{type=1,data=new INPUTUNION{key=new KEYBDINPUT{vk=(ushort)vk,flags=up?2u:0u}}};if(SendInput(1,new[]{input},Marshal.SizeOf(typeof(INPUT)))!=1)throw new Exception("SendInput failed "+Marshal.GetLastWin32Error());}
 void Pair(int vk){steps.Enqueue(()=>Key(vk,false));steps.Enqueue(()=>Key(vk,true));}
 int Mode(){IntPtr c=NativeIme.ImmGetContext(edit.Handle);try{int mode,sentence;NativeIme.ImmGetConversionStatus(c,out mode,out sentence);return mode;}finally{NativeIme.ImmReleaseContext(edit.Handle,c);}}
 void Reset(){IntPtr c=NativeIme.ImmGetContext(edit.Handle);try{NativeIme.ImmSetOpenStatus(c,true);NativeIme.ImmSetConversionStatus(c,0x401,0);}finally{NativeIme.ImmReleaseContext(edit.Handle,c);}edit.Clear();baseline=Mode();}
 void Case(string label,int sequence){steps.Enqueue(()=>{Reset();log.AppendLine("BEGIN "+label+" mode="+baseline.ToString("X"));});if(sequence==0){for(int i=0;i<20;i++)Pair(0xA0);}if(sequence==1){steps.Enqueue(()=>Key(0xA0,false));Pair(0x52);Pair(0x20);steps.Enqueue(()=>Key(0xA0,true));}if(sequence==2){steps.Enqueue(()=>Key(0xA0,false));Pair(0x20);steps.Enqueue(()=>Key(0xA0,true));}steps.Enqueue(()=>log.AppendLine("END "+label+" mode="+Mode().ToString("X")+" text="+edit.Text));Pair(0x1B);}
 void Build(){steps.Enqueue(()=>log.AppendLine("foreground="+(NativeIme.GetForegroundWindow()==Handle)+" Setting="+Registry.GetValue(@"HKEY_CURRENT_USER\"+Setting,"EnableFullHalfWidthSwitchKey","absent")));
  Case("original: Shift-only",0);Case("original: Shift-R-Space",1);Case("original: Shift-Space",2);
  steps.Enqueue(()=>{restore=true;bool ok=ImmSetHotKey(0x11,0,0,IntPtr.Zero);uint mod,key;IntPtr h;bool exists=ImmGetHotKey(0x11,out mod,out key,out h);log.AppendLine("Disable legacy: ok="+ok+" exists="+exists+" key="+key+" mod="+mod);});
  Case("legacy disabled: Shift-only",0);Case("legacy disabled: Shift-R-Space",1);Case("legacy disabled: Shift-Space",2);
  steps.Enqueue(()=>{ImmSetHotKey(0x11,oldMod,oldKey,oldLayout);restore=false;log.AppendLine("Legacy restored");});
  Case("restored: Shift-R-Space",1);
  steps.Enqueue(()=>{Reset();log.AppendLine("BEGIN normal Chinese nihao");});foreach(int k in new[]{0x4E,0x49,0x48,0x41,0x4F,0x20})Pair(k);
  steps.Enqueue(()=>log.AppendLine("Chinese text="+edit.Text+" mode="+Mode().ToString("X")));
  steps.Enqueue(()=>{Reset();log.AppendLine("BEGIN uppercase with space");});steps.Enqueue(()=>Key(0xA0,false));Pair(0x52);Pair(0x20);steps.Enqueue(()=>Key(0xA0,true));Pair(0x0D);
  steps.Enqueue(()=>log.AppendLine("Committed uppercase text="+edit.Text.Replace("\r","\\r").Replace("\n","\\n")+" mode="+Mode().ToString("X")));
  steps.Enqueue(()=>Reset());Pair(0xA0);foreach(int k in new[]{0x41,0x42,0x43,0x31,0x32,0x33})Pair(k);
  steps.Enqueue(()=>log.AppendLine("English switch text="+edit.Text+" mode="+Mode().ToString("X")));
  steps.Enqueue(()=>Reset());Pair(0xBE);Pair(0xBC);
  steps.Enqueue(()=>log.AppendLine("Chinese punctuation="+edit.Text));
  steps.Enqueue(()=>Reset());
 }
}
