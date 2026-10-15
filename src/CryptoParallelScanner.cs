using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

public sealed class CryptoCpuPlan
{
    public int AvailablePhysicalCores, SelectedPhysicalCores, AvailableLogicalProcessors, SelectedLogicalProcessors;
    public int RequestedCorePercent;
    public double EffectiveCorePercent;
    public bool MinimumCoreApplied;
    public ulong Mask;

    public int GetWorkerCount(int requested)
    {
        if (requested < 0 || requested > 32) throw new ArgumentOutOfRangeException("requested");
        return Math.Min(SelectedPhysicalCores, requested == 0 ? 32 : requested);
    }
}

// Restrict the whole process, including discovery, GC and inherited PDF processes.
public sealed class CryptoCpuBudget : IDisposable
{
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetLogicalProcessorInformationEx(int relationship, IntPtr buffer, ref uint length);
    [DllImport("kernel32.dll")] static extern ushort GetActiveProcessorGroupCount();
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetProcessAffinityMask(IntPtr process, out UIntPtr mask, out UIntPtr systemMask);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetProcessAffinityMask(IntPtr process, UIntPtr mask);
    private readonly Process process;
    private readonly UIntPtr originalMask;
    private bool disposed;
    public readonly CryptoCpuPlan Plan;

    public static CryptoCpuPlan Select(ulong[] cores, ulong allowed)
    {
        return Select(cores, allowed, 50);
    }
    public static CryptoCpuPlan Select(ulong[] cores, ulong allowed, int corePercent)
    {
        if (cores == null) throw new ArgumentNullException("cores");
        if (corePercent < 1 || corePercent > 100) throw new ArgumentOutOfRangeException("corePercent");
        List<ulong> eligible = new List<ulong>();
        foreach (ulong core in cores) if ((core & allowed) != 0) eligible.Add(core & allowed);
        if (eligible.Count == 0) throw new InvalidOperationException("No hay núcleos físicos disponibles para el escáner.");
        int calculated = (int)((long)eligible.Count * corePercent / 100);
        int selected = Math.Max(1, calculated);
        ulong mask = 0;
        for (int i = 0; i < selected; i++) mask |= eligible[i];
        return new CryptoCpuPlan { AvailablePhysicalCores = eligible.Count, SelectedPhysicalCores = selected,
            AvailableLogicalProcessors = Bits(allowed), SelectedLogicalProcessors = Bits(mask), Mask = mask,
            RequestedCorePercent = corePercent, EffectiveCorePercent = 100.0 * selected / eligible.Count,
            MinimumCoreApplied = calculated == 0 };
    }
    private static int Bits(ulong value) { int count = 0; while (value != 0) { value &= value - 1; count++; } return count; }
    public CryptoCpuBudget() : this(50) { }
    public CryptoCpuBudget(int corePercent)
    {
        if (corePercent < 1 || corePercent > 100) throw new ArgumentOutOfRangeException("corePercent");
        if (GetActiveProcessorGroupCount() != 1)
            throw new InvalidOperationException("El límite de CPU requiere un solo grupo de procesadores de Windows (hasta 64 procesadores lógicos). No se inicia el escaneo sin ese límite.");
        process = Process.GetCurrentProcess();
        UIntPtr systemMask;
        if (!GetProcessAffinityMask(process.Handle, out originalMask, out systemMask)) throw new Win32Exception(Marshal.GetLastWin32Error());
        uint length = 0;
        GetLogicalProcessorInformationEx(0, IntPtr.Zero, ref length);
        if (length < 32 || length > 1024 * 1024) throw new InvalidOperationException("No se pudo consultar la topología del procesador.");
        IntPtr buffer = Marshal.AllocHGlobal((int)length);
        try {
            if (!GetLogicalProcessorInformationEx(0, buffer, ref length)) throw new Win32Exception(Marshal.GetLastWin32Error());
            List<ulong> cores = new List<ulong>();
            for (int offset = 0; offset < length; ) {
                IntPtr item = IntPtr.Add(buffer, offset);
                int size = Marshal.ReadInt32(item, 4);
                if (size < 32 || size > length - offset || Marshal.ReadInt32(item) != 0) throw new InvalidOperationException("Topología de CPU no válida.");
                int count = (ushort)Marshal.ReadInt16(item, 30), stride = IntPtr.Size + 8;
                if (count < 1 || 32 + count * stride > size) throw new InvalidOperationException("Afinidad de CPU no válida.");
                for (int group = 0; group < count; group++) {
                    int pos = 32 + group * stride;
                    if (Marshal.ReadInt16(item, pos + IntPtr.Size) != 0) throw new InvalidOperationException("Grupo de CPU no compatible.");
                    ulong mask = IntPtr.Size == 8 ? unchecked((ulong)Marshal.ReadInt64(item, pos)) : unchecked((uint)Marshal.ReadInt32(item, pos));
                    cores.Add(mask);
                }
                offset += size;
            }
            Plan = Select(cores.ToArray(), originalMask.ToUInt64(), corePercent);
            if (!SetProcessAffinityMask(process.Handle, new UIntPtr(Plan.Mask))) throw new Win32Exception(Marshal.GetLastWin32Error());
            UIntPtr actual;
            if (!GetProcessAffinityMask(process.Handle, out actual, out systemMask) || actual.ToUInt64() != Plan.Mask) {
                SetProcessAffinityMask(process.Handle, originalMask);
                throw new InvalidOperationException("No se pudo verificar el límite de CPU; no se inicia el escaneo.");
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        try { if (!SetProcessAffinityMask(process.Handle, originalMask)) throw new Win32Exception(Marshal.GetLastWin32Error()); }
        finally { process.Dispose(); }
    }
}

public sealed class CryptoScanWorkItem
{
    public readonly string Path, PathId;
    public readonly CryptoScanItem Info;
    public readonly CryptoScanCacheEntry Cached;
    public readonly bool Json, HexContext;
    public readonly string[] PathEvidence;
    internal long ProgressBytes;
    public CryptoScanWorkItem(string path, string pathId, CryptoScanItem info, CryptoScanCacheEntry cached, bool json, bool hexContext, string[] pathEvidence)
    { Path = path; PathId = pathId; Info = info; Cached = cached; Json = json; HexContext = hexContext; PathEvidence = pathEvidence; }
}
public sealed class CryptoCompletedScan
{
    public CryptoScanWorkItem Work;
    public CryptoFileScanResult Result;
    public bool Reused, Failed;
}
public sealed class CryptoParallelSnapshot
{
    public long BytesRead, PendingWork;
    public int Active, Outstanding, MaximumActive, QueueCapacity, WorkerCount;
}

// Only managed data crosses worker boundaries; PowerShell owns findings/cache/output.
public sealed class CryptoParallelScanner : IDisposable
{
    private readonly BlockingCollection<CryptoScanWorkItem> queue;
    private readonly ConcurrentQueue<CryptoCompletedScan> completed = new ConcurrentQueue<CryptoCompletedScan>();
    private readonly HashSet<CryptoScanWorkItem> pending = new HashSet<CryptoScanWorkItem>();
    private readonly object gate = new object();
    private readonly CancellationTokenSource cancellation = new CancellationTokenSource();
    private readonly Thread[] workers;
    private readonly long maxBytes;
    private readonly bool useCache;
    private long bytesRead;
    private int active, maximumActive;
    private bool disposed;
    public readonly int WorkerCount, QueueCapacity;

    public CryptoParallelScanner(int workerCount, long maxBytes, bool useCache)
    {
        if (workerCount < 1 || workerCount > 32) throw new ArgumentOutOfRangeException("workerCount");
        WorkerCount = workerCount; QueueCapacity = workerCount * 2;
        this.maxBytes = maxBytes; this.useCache = useCache;
        queue = new BlockingCollection<CryptoScanWorkItem>(QueueCapacity);
        workers = new Thread[workerCount];
        for (int i = 0; i < workers.Length; i++) {
            workers[i] = new Thread(Consume) { IsBackground = true, Name = "Crypto artifact reader " + (i + 1) };
            workers[i].Start();
        }
    }
    public bool TrySubmit(CryptoScanWorkItem work)
    {
        cancellation.Token.ThrowIfCancellationRequested();
        lock (gate) {
            // Bound queued, active AND unconsumed results, not just the input queue.
            if (pending.Count >= QueueCapacity + WorkerCount) return false;
            pending.Add(work);
            if (queue.TryAdd(work)) return true;
            pending.Remove(work);
            return false;
        }
    }
    public CryptoCompletedScan TakeCompleted(int waitMilliseconds)
    {
        Stopwatch timer = Stopwatch.StartNew();
        do {
            CryptoCompletedScan result;
            if (completed.TryDequeue(out result)) return result;
            if (timer.ElapsedMilliseconds >= waitMilliseconds) return null;
            Thread.Sleep(10);
        } while (true);
    }
    public void Acknowledge(CryptoCompletedScan result) { lock (gate) pending.Remove(result.Work); }
    public CryptoParallelSnapshot GetSnapshot()
    {
        lock (gate) {
            long work = 0;
            foreach (CryptoScanWorkItem item in pending) work += Math.Min(item.Info.Length, Interlocked.Read(ref item.ProgressBytes));
            return new CryptoParallelSnapshot { BytesRead = Interlocked.Read(ref bytesRead), PendingWork = work,
                Active = active, Outstanding = pending.Count, MaximumActive = maximumActive, WorkerCount = WorkerCount, QueueCapacity = QueueCapacity };
        }
    }
    private void Consume()
    {
        CryptoFileScanner.Cancellation = cancellation.Token;
        try {
            foreach (CryptoScanWorkItem work in queue.GetConsumingEnumerable(cancellation.Token)) {
                lock (gate) { active++; maximumActive = Math.Max(maximumActive, active); }
                try { completed.Enqueue(Analyze(work)); }
                catch (OperationCanceledException) { break; }
                finally { lock (gate) active--; }
            }
        }
        catch (OperationCanceledException) { }
        finally { CryptoFileScanner.Cancellation = CancellationToken.None; }
    }
    private CryptoCompletedScan Analyze(CryptoScanWorkItem work)
    {
        CryptoCompletedScan response = new CryptoCompletedScan { Work = work };
        try {
            bool verify = useCache && work.Cached != null && work.Cached.Length == work.Info.Length && work.Cached.LastWriteTicks == work.Info.LastWriteTicks;
            CryptoFileScanResult result = Read(work, !verify);
            if (verify && result.Sha256 == work.Cached.Hash) {
                result.Evidence = work.Cached.Evidence; result.MembersScanned = work.Cached.MembersScanned; result.MembersSkipped = work.Cached.MembersSkipped;
                response.Reused = true;
            }
            else if (verify) result = Read(work, true);
            CryptoScanItem after = CryptoWindowsIO.GetInfo(work.Path);
            if (after.Length != work.Info.Length || after.LastWriteTicks != work.Info.LastWriteTicks || result.BytesRead != work.Info.Length)
                throw new IOException("El archivo cambió durante el escaneo.");
            response.Result = result;
        }
        catch (OperationCanceledException) { throw; }
        catch { response.Failed = true; }
        return response;
    }
    private CryptoFileScanResult Read(CryptoScanWorkItem work, bool analyze)
    {
        long reported = 0;
        CryptoFileScanResult result = CryptoFileScanner.ReadFile(work.Path, analyze, work.Json, work.HexContext, maxBytes, useCache,
            read => {
                cancellation.Token.ThrowIfCancellationRequested();
                long delta = read - reported;
                if (delta > 0) Interlocked.Add(ref bytesRead, delta);
                reported = read;
                Interlocked.Exchange(ref work.ProgressBytes, Math.Max(Interlocked.Read(ref work.ProgressBytes), read));
            });
        Interlocked.Add(ref bytesRead, result.BytesRead - reported);
        Interlocked.Exchange(ref work.ProgressBytes, Math.Max(Interlocked.Read(ref work.ProgressBytes), result.BytesRead));
        return result;
    }
    public void Cancel() { cancellation.Cancel(); }
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        cancellation.Cancel();
        queue.CompleteAdding();
        foreach (Thread worker in workers) worker.Join();
        queue.Dispose(); cancellation.Dispose();
    }
}
