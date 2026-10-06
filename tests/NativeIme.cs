using System;
using System.Runtime.InteropServices;

namespace PinyinShiftFixTests
{
    // Only the interop calls required by the foreground-only test harness.
    internal static class NativeIme
    {
        [DllImport("user32.dll")] internal static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] internal static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
        [DllImport("imm32.dll")] internal static extern IntPtr ImmGetContext(IntPtr hwnd);
        [DllImport("imm32.dll")] internal static extern bool ImmReleaseContext(IntPtr hwnd, IntPtr context);
        [DllImport("imm32.dll")] internal static extern bool ImmGetConversionStatus(IntPtr context, out int conversion, out int sentence);
        [DllImport("imm32.dll")] internal static extern bool ImmSetConversionStatus(IntPtr context, int conversion, int sentence);
        [DllImport("imm32.dll")] internal static extern bool ImmSetOpenStatus(IntPtr context, bool open);
    }
}
