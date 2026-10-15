using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

public sealed class CryptoInventorySnapshot
{
    public long RootFiles, RootWork, TotalFiles, TotalCandidates, CandidateBytes, TotalWork, PriorWork, Errors;
    public bool RootComplete, AllComplete;
}

// Metadata discovery runs independently of content scanning and retains only per-root totals.
public sealed class CryptoScanInventory : IDisposable
{
    private sealed class Totals { public long Files, Candidates, Bytes, Errors; public bool Complete; }
    private readonly object gate = new object();
    private readonly string[] roots;
    private readonly Totals[] totals;
    private readonly HashSet<string> content, skipped, excludedDirectories, excludedDirectoryPaths, excludedFiles;
    private readonly Regex dotEnv, browser, walletPath, walletName;
    private readonly long maxBytes;
    private readonly CancellationTokenSource cancellation = new CancellationTokenSource();
    private readonly Task task;
    public CryptoScanInventory(string[] roots, string[] content, string[] skipped, string[] excludedDirectories,
        string[] excludedDirectoryPaths, string[] excludedFiles, long maxBytes, string dotEnv, string browser, string walletPath, string walletName)
    {
        this.roots = (string[])roots.Clone(); this.maxBytes = maxBytes;
        this.content = Set(content); this.skipped = Set(skipped);
        this.excludedDirectories = Set(excludedDirectories);
        this.excludedDirectoryPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string path in excludedDirectoryPaths) this.excludedDirectoryPaths.Add(NormalizeDirectory(path));
        this.excludedFiles = Set(excludedFiles);
        this.dotEnv = Pattern(dotEnv); this.browser = Pattern(browser);
        this.walletPath = Pattern(walletPath); this.walletName = Pattern(walletName);
        totals = new Totals[roots.Length];
        for (int i = 0; i < totals.Length; i++) totals[i] = new Totals();
        task = Task.Run((Action)Discover);
    }
    private static HashSet<string> Set(string[] values)
    { return new HashSet<string>(values, StringComparer.OrdinalIgnoreCase); }
    private static string NormalizeDirectory(string path)
    { return CryptoWindowsIO.NormalizePath(path).TrimEnd('\\'); }
    private static Regex Pattern(string value)
    { return new Regex(value, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(3)); }
    private bool Eligible(CryptoScanItem item)
    {
        string extension = Path.GetExtension(item.Name);
        if (skipped.Contains(extension)) return false;
        return content.Contains(extension) || dotEnv.IsMatch(item.Name) || browser.IsMatch(item.FullName)
            || walletPath.IsMatch(item.FullName) || walletName.IsMatch(item.Name);
    }
    private void Discover()
    {
        try
        {
            for (int index = 0; index < roots.Length && !cancellation.IsCancellationRequested; index++)
            {
                Stack<string> pending = new Stack<string>(); pending.Push(roots[index]);
                while (pending.Count > 0 && !cancellation.IsCancellationRequested)
                {
                    string directory = pending.Pop();
                    try
                    {
                        foreach (CryptoScanItem item in CryptoWindowsIO.Enumerate(directory))
                        {
                            if (cancellation.IsCancellationRequested) break;
                            if ((item.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                            if ((item.Attributes & FileAttributes.Directory) != 0)
                            {
                                bool systemDirectory = excludedDirectories.Contains(item.Name) && CryptoWindowsIO.IsVolumeRootChild(item.FullName);
                                if (!systemDirectory && !excludedDirectoryPaths.Contains(NormalizeDirectory(item.FullName))) pending.Push(item.FullName);
                                continue;
                            }
                            if (excludedFiles.Contains(item.FullName)) continue;
                            bool eligible = false;
                            try { eligible = item.Length <= maxBytes && Eligible(item); }
                            catch { lock (gate) totals[index].Errors++; }
                            lock (gate)
                            {
                                totals[index].Files++;
                                if (eligible) { totals[index].Candidates++; totals[index].Bytes += item.Length; }
                            }
                        }
                    }
                    catch { lock (gate) totals[index].Errors++; }
                }
                if (!cancellation.IsCancellationRequested) lock (gate) totals[index].Complete = true;
            }
        }
        catch
        {
            lock (gate) foreach (Totals root in totals) { root.Errors++; root.Complete = true; }
        }
    }
    public CryptoInventorySnapshot GetSnapshot(int index)
    {
        if (index < 0 || index >= totals.Length) throw new ArgumentOutOfRangeException("index");
        lock (gate)
        {
            CryptoInventorySnapshot snapshot = new CryptoInventorySnapshot { AllComplete = true };
            for (int i = 0; i < totals.Length; i++)
            {
                Totals root = totals[i]; long work = root.Bytes + root.Files * 4096L;
                snapshot.TotalFiles += root.Files; snapshot.TotalCandidates += root.Candidates;
                snapshot.CandidateBytes += root.Bytes; snapshot.TotalWork += work; snapshot.Errors += root.Errors;
                snapshot.AllComplete &= root.Complete;
                if (i < index) snapshot.PriorWork += work;
                if (i == index) { snapshot.RootFiles = root.Files; snapshot.RootWork = work; snapshot.RootComplete = root.Complete; }
            }
            return snapshot;
        }
    }
    public void Dispose()
    {
        cancellation.Cancel();
        try { task.Wait(2000); } catch {}
        if (task.IsCompleted) cancellation.Dispose();
        else task.ContinueWith(ignored => cancellation.Dispose(), TaskScheduler.Default);
    }
}
