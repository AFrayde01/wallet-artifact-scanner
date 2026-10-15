using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public sealed class CryptoScanItem
{
    public string FullName;
    public string Name;
    public FileAttributes Attributes;
    public long Length;
    public long LastWriteTicks;
}

public sealed class CryptoVolumeIdentity
{
    public string MountRoot;
    public string Identifier;
    public string FileSystem;
    public string LocationKey;
}

// All native operations below query metadata or open files for reading.
public static class CryptoWindowsIO
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FindData
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint SizeHigh, SizeLow, Reserved0, Reserved1;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Name;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string AlternateName;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct AttributeData
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint SizeHigh, SizeLow;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstFileW(string path, out FindData data);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool FindNextFileW(IntPtr handle, out FindData data);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool FindClose(IntPtr handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetFileAttributesExW(string path, int level, out AttributeData data);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFullPathNameW(string path, uint size, StringBuilder result, IntPtr filePart);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetVolumePathNameW(string path, StringBuilder result, uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetVolumeNameForVolumeMountPointW(string path, StringBuilder result, uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetVolumeInformationW(string path, StringBuilder label, uint labelSize, out uint serial, out uint componentLength, out uint flags, StringBuilder fileSystem, uint fsSize);
    [StructLayout(LayoutKind.Sequential)]
    private struct BasicJobLimits
    {
        public long ProcessTime, JobTime; public uint Flags;
        public UIntPtr MinimumWorkingSet, MaximumWorkingSet; public uint ActiveProcesses;
        public UIntPtr Affinity; public uint Priority, Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters { public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)]
    private struct JobLimits
    {
        public BasicJobLimits Basic; public IoCounters Io;
        public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateJobObjectW(IntPtr security, string name);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(IntPtr job, int level, ref JobLimits limits, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);

    public static IntPtr BoundWorker(IntPtr process)
    {
        IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw Error();
        JobLimits limits = new JobLimits { Basic = new BasicJobLimits { Flags = 0x2100 }, ProcessMemory = new UIntPtr(512U * 1024U * 1024U) };
        if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(JobLimits))) || !AssignProcessToJobObject(job, process))
        { IOException error = Error(); CloseHandle(job); throw error; }
        return job;
    }
    public static void CloseWorkerJob(IntPtr job) { if (job != IntPtr.Zero) CloseHandle(job); }

    private static IOException Error() { return new IOException("Windows file operation failed.", new Win32Exception(Marshal.GetLastWin32Error())); }
    public static string NormalizePath(string path)
    {
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) path = @"\\" + path.Substring(8);
        else if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) path = path.Substring(4);
        StringBuilder result = new StringBuilder(Math.Min(32768, Math.Max(512, path.Length + 256)));
        uint size = GetFullPathNameW(path, (uint)result.Capacity, result, IntPtr.Zero);
        if (size >= result.Capacity && size < 32768) { result = new StringBuilder((int)size + 1); size = GetFullPathNameW(path, (uint)result.Capacity, result, IntPtr.Zero); }
        if (size == 0 || size >= result.Capacity) throw Error();
        return result.ToString();
    }
    public static string ExtendedPath(string path)
    {
        return PrefixPath(NormalizePath(path));
    }
    private static string PrefixPath(string path)
    {
        return path.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + path.Substring(2) : @"\\?\" + path;
    }
    private static long Ticks(System.Runtime.InteropServices.ComTypes.FILETIME time)
    {
        long value = ((long)(uint)time.dwHighDateTime << 32) | (uint)time.dwLowDateTime;
        return DateTime.FromFileTimeUtc(value).Ticks;
    }
    public static string RootPath(string path)
    {
        path = NormalizePath(path);
        if (!path.StartsWith(@"\\", StringComparison.Ordinal)) return path.Substring(0, 3);
        int server = path.IndexOf('\\', 2), share = server < 0 ? -1 : path.IndexOf('\\', server + 1);
        return share < 0 ? path.TrimEnd('\\') + "\\" : path.Substring(0, share + 1);
    }
    public static bool IsVolumeRootChild(string path)
    {
        string normalized = NormalizePath(path);
        string root = RootPath(normalized);
        normalized = normalized.TrimEnd('\\');
        return normalized.Length > root.Length && normalized.StartsWith(root, StringComparison.OrdinalIgnoreCase) &&
            normalized.IndexOf('\\', root.Length) < 0;
    }
    public static CryptoScanItem GetInfo(string path)
    { CryptoScanItem result = TryGetInfo(path); if (result == null) throw new FileNotFoundException("Location no longer exists."); return result; }
    public static CryptoScanItem TryGetInfo(string path)
    {
        AttributeData data;
        path = NormalizePath(path);
        if (!GetFileAttributesExW(PrefixPath(path), 0, out data)) { int error = Marshal.GetLastWin32Error(); if (error == 2 || error == 3) return null; throw Error(); }
        return new CryptoScanItem { FullName = path, Name = Path.GetFileName(path.TrimEnd('\\')), Attributes = (FileAttributes)data.Attributes,
            Length = ((long)data.SizeHigh << 32) | data.SizeLow, LastWriteTicks = Ticks(data.Write) };
    }
    public static IEnumerable<CryptoScanItem> Enumerate(string directory)
    {
        directory = NormalizePath(directory).TrimEnd('\\') + "\\";
        FindData data;
        IntPtr handle = FindFirstFileW(PrefixPath(directory) + "*", out data);
        if (handle == new IntPtr(-1))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == 2) yield break;
            throw Error();
        }
        try
        {
            do
            {
                if (data.Name == "." || data.Name == "..") continue;
                yield return new CryptoScanItem { FullName = directory + data.Name, Name = data.Name, Attributes = (FileAttributes)data.Attributes,
                    Length = ((long)data.SizeHigh << 32) | data.SizeLow, LastWriteTicks = Ticks(data.Write) };
            } while (FindNextFileW(handle, out data));
            if (Marshal.GetLastWin32Error() != 18) throw Error();
        }
        finally { FindClose(handle); }
    }
    public static FileStream OpenRead(string path)
    {
        SafeFileHandle handle = CreateFileW(ExtendedPath(path), 0x80000000, 1, IntPtr.Zero, 3, 0x08000000, IntPtr.Zero);
        if (handle.IsInvalid) { IOException error = Error(); handle.Dispose(); throw error; }
        try { return new FileStream(handle, FileAccess.Read, 65536, false); }
        catch { handle.Dispose(); throw; }
    }
    public static CryptoVolumeIdentity Identify(string location)
    {
        location = NormalizePath(location);
        StringBuilder mount = new StringBuilder(32768);
        if (!GetVolumePathNameW(ExtendedPath(location), mount, (uint)mount.Capacity)) throw Error();
        string root = NormalizePath(mount.ToString()).TrimEnd('\\') + "\\";
        StringBuilder guid = new StringBuilder(128);
        string identity;
        if (GetVolumeNameForVolumeMountPointW(root, guid, (uint)guid.Capacity)) identity = guid.ToString().ToUpperInvariant();
        else if (root.StartsWith(@"\\", StringComparison.Ordinal)) identity = "UNC:" + root.ToUpperInvariant();
        else throw Error();
        uint serial, componentLength, flags;
        StringBuilder fileSystem = new StringBuilder(64);
        if (!GetVolumeInformationW(root, null, 0, out serial, out componentLength, out flags, fileSystem, (uint)fileSystem.Capacity)) throw Error();
        identity += "|" + serial.ToString("x8");
        string relative = location.Length >= root.Length ? location.Substring(root.Length).TrimEnd('\\') : "";
        return new CryptoVolumeIdentity { MountRoot = root, Identifier = CryptoFileScanner.TextHash(identity), FileSystem = fileSystem.ToString(),
            LocationKey = CryptoFileScanner.TextHash(identity + "|" + relative.ToUpperInvariant()) };
    }
}

public sealed class CryptoConsoleInputSession : IDisposable {
    [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int identifier);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetConsoleMode(IntPtr handle, out uint mode);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetConsoleMode(IntPtr handle, uint mode);
    private readonly IntPtr input;
    private readonly uint originalMode;
    private bool adjusted;
    public readonly bool IsConsole, Protected;
    public static uint ScanMode(uint mode) { return (mode | 0x0080U) & ~0x0040U; }
    public CryptoConsoleInputSession() {
        input = GetStdHandle(-10);
        if (input == IntPtr.Zero || input == new IntPtr(-1) || !GetConsoleMode(input, out originalMode)) return;
        IsConsole = true;
        uint mode = ScanMode(originalMode);
        if (mode == originalMode) { Protected = true; return; }
        if (!SetConsoleMode(input, mode)) return;
        adjusted = true;
        uint actual;
        Protected = GetConsoleMode(input, out actual) && (actual & 0x0040U) == 0;
    }
    public void Dispose() {
        if (!adjusted) return;
        adjusted = false;
        SetConsoleMode(input, originalMode);
    }
}
