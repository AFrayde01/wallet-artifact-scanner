using System;
using System.Collections.Generic;
using System.Collections;
using System.IO;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

public sealed class Bip39StructuralMatch
{
    public int Start, End, Line, Column, WordCount, UniqueWords, InvalidSeparators;
    public string Language, Structure, Numbering;
    public bool PublicExample, EmbeddedIdentifier;
}
public sealed class Bip39StructuralResult
{
    public Bip39StructuralMatch[] Matches;
    public bool Truncated;
}
public static class CryptoBip39Inspector
{
    private static Dictionary<string,int>[] Lists;
    private static HashSet<string> PublicEntropies;
    private static readonly Regex Words = new Regex(@"[\p{L}\p{M}]+", RegexOptions.Compiled);
    private static readonly Regex Numbered = new Regex(@"^\s+(\d{1,2})[.)]\s+$", RegexOptions.Compiled);
    private static readonly Regex Comma = new Regex(@"^\s*['"" ]?\s*,\s*['"" ]?\s*$", RegexOptions.Compiled);
    private static readonly int[] Lengths = {12,15,18,21,24};
    private static string Normalize(string word) { return word.ToLowerInvariant().Normalize(NormalizationForm.FormKD); }
    public static void Configure(string[] english, string[] spanish, string[] examples)
    {
        Lists = new Dictionary<string,int>[2];
        string[][] sources = {english,spanish};
        for (int language=0; language<2; language++)
        {
            if (sources[language].Length != 2048) throw new ArgumentException("Expected a complete BIP39 word list.");
            Lists[language] = new Dictionary<string,int>(StringComparer.Ordinal);
            for (int i=0;i<2048;i++) Lists[language].Add(Normalize(sources[language][i].Trim()),i);
        }
        PublicEntropies = new HashSet<string>(examples,StringComparer.OrdinalIgnoreCase);
    }
    private static bool Identifier(char c) { return Char.IsLetterOrDigit(c) || c=='_' || Char.GetUnicodeCategory(c)==UnicodeCategory.NonSpacingMark; }
    private static bool Checksum(List<int> indices, int count, out string entropyHex)
    {
        int entropyBits=count*11*32/33, offset=indices.Count-count;
        byte[] entropy=new byte[entropyBits/8];
        for (int bit=0;bit<entropyBits;bit++) entropy[bit/8]|=(byte)(((indices[offset+bit/11]>>(10-bit%11))&1)<<(7-bit%8));
        byte[] digest; using (SHA256 sha=SHA256.Create()) digest=sha.ComputeHash(entropy);
        for (int bit=entropyBits;bit<count*11;bit++)
            if (((indices[offset+bit/11]>>(10-bit%11))&1)!=((digest[(bit-entropyBits)/8]>>(7-(bit-entropyBits)%8))&1)) { entropyHex=""; return false; }
        entropyHex=BitConverter.ToString(entropy).Replace("-","").ToLowerInvariant(); return true;
    }
    public static Bip39StructuralResult Inspect(string text, int maximum)
    {
        if (Lists==null || maximum<1) throw new InvalidOperationException("Inspector is not configured.");
        var found=new List<Bip39StructuralMatch>();
        var sequences=new List<int>[] {new List<int>(24),new List<int>(24)};
        var positions=new List<Match>[] {new List<Match>(24),new List<Match>(24)};
        int line=1, lineStart=0, lineCursor=0;
        foreach (Match token in Words.Matches(text))
        {
            string normalized=Normalize(token.Value);
            for (int language=0;language<2;language++)
            {
                int index;
                if (!Lists[language].TryGetValue(normalized,out index)) { sequences[language].Clear(); positions[language].Clear(); continue; }
                var sequence=sequences[language]; var spans=positions[language];
                sequence.Add(index); spans.Add(token);
                if (sequence.Count>24) { sequence.RemoveAt(0); spans.RemoveAt(0); }
                foreach (int count in Lengths)
                {
                    string entropy;
                    if (sequence.Count<count || !Checksum(sequence,count,out entropy)) continue;
                    if (found.Count>=maximum) return new Bip39StructuralResult {Matches=found.ToArray(),Truncated=true};
                    int first=sequence.Count-count, bad=0, numbered=0, commas=0, expected=-1;
                    bool embedded=false, ascending=true, numberingOk=true;
                    var unique=new HashSet<int>();
                    for (int i=first;i<sequence.Count;i++)
                    {
                        Match word=spans[i]; unique.Add(sequence[i]);
                        if (word.Index>0 && Identifier(text[word.Index-1]) || word.Index+word.Length<text.Length && Identifier(text[word.Index+word.Length])) embedded=true;
                        if (i==first) continue;
                        if (sequence[i]!=sequence[i-1]+1) ascending=false;
                        int gapStart=spans[i-1].Index+spans[i-1].Length, gapLength=word.Index-gapStart;
                        if (gapLength>256 || gapLength<1) { bad++; continue; }
                        string gap=text.Substring(gapStart,gapLength);
                        Match label=Numbered.Match(gap);
                        if (label.Success)
                        {
                            int value=Int32.Parse(label.Groups[1].Value,CultureInfo.InvariantCulture);
                            numbered++; if (expected>=0 && value!=expected) numberingOk=false; expected=value+1;
                        }
                        else if (Comma.IsMatch(gap)) commas++;
                        else if (!String.IsNullOrWhiteSpace(gap)) bad++;
                    }
                    Match start=spans[first];
                    // Windows overlap between 12/15/18/21/24; compute line independently.
                    if (start.Index<lineCursor) { line=1; lineStart=0; lineCursor=0; }
                    for (;lineCursor<start.Index;lineCursor++) if (text[lineCursor]=='\n') { line++; lineStart=lineCursor+1; }
                    bool example=PublicEntropies.Contains(entropy);
                    string structure=example?"public_example":embedded?"embedded_identifier":bad>0?"fragmented":!numberingOk?"inconsistent_numbering":ascending?"dictionary_sequence":unique.Count<4?"repetitive_sequence":numbered>0?"numbered_list":commas>0?"comma_list":"continuous_text";
                    found.Add(new Bip39StructuralMatch { Start=start.Index,End=token.Index+token.Length,Line=line,Column=start.Index-lineStart+1,WordCount=count,UniqueWords=unique.Count,InvalidSeparators=bad,Language=language==0?"en":"es",Structure=structure,Numbering=numbered==0?"not_present":numberingOk?"consistent":"inconsistent",PublicExample=example,EmbeddedIdentifier=embedded });
                }
            }
        }
        return new Bip39StructuralResult {Matches=found.ToArray(),Truncated=false};
    }
    public static bool SameSequence(string alternative, string original, int start, int end)
    {
        // Compare only in memory; never return tokens or a phrase-derived identifier.
        var target=new List<string>(); foreach (Match word in Words.Matches(original.Substring(start,end-start))) target.Add(Normalize(word.Value));
        var window=new Queue<string>();
        foreach (Match word in Words.Matches(alternative))
        {
            window.Enqueue(Normalize(word.Value)); if(window.Count>target.Count) window.Dequeue();
            if(window.Count!=target.Count) continue;
            int i=0; bool equal=true; foreach(string value in window) if(value!=target[i++]) { equal=false; break; }
            if(equal) return true;
        }
        return false;
    }
    public static string SafeLabel(string label)
    {
        int known=0;
        foreach(Match word in Words.Matches(label))
        {
            string value=Normalize(word.Value);
            if(Lists[0].ContainsKey(value)||Lists[1].ContainsKey(value)) { if(++known>=10) return "[SENSITIVE_NAME_REDACTED]"; }
            else known=0;
        }
        label=Regex.Replace(label,@"\[\s*(?:[0-9]{1,3}\s*,\s*){63}[0-9]{1,3}\s*\]","[SENSITIVE_KEY_ARRAY_REDACTED]");
        return Regex.Replace(label,@"(?i)[0-9a-f]{40,}|[A-Za-z0-9+/=_-]{40,}","[REDACTED]");
    }
    private sealed class PositionedLetter { public string Text; public double X,Y,EndX,Size; public int Row,Order; }
    public static string GeometryText(IEnumerable letters, int maximum)
    {
        // Public PdfPig letter properties, with no compile-time dependency on its assemblies.
        var records=new List<PositionedLetter>(); int order=0;
        System.Reflection.PropertyInfo value=null,baseline=null,end=null,size=null,x=null,y=null;
        foreach(object letter in letters)
        {
            if(records.Count>=maximum) throw new InvalidOperationException("Page geometry limit.");
            if(value==null)
            {
                Type type=letter.GetType(); value=type.GetProperty("Value"); baseline=type.GetProperty("StartBaseLine");
                end=type.GetProperty("EndBaseLine"); size=type.GetProperty("PointSize");
                Type point=baseline.PropertyType; x=point.GetProperty("X"); y=point.GetProperty("Y");
            }
            object start=baseline.GetValue(letter,null), finish=end.GetValue(letter,null);
            double yy=Convert.ToDouble(y.GetValue(start,null),CultureInfo.InvariantCulture);
            records.Add(new PositionedLetter {Text=(string)value.GetValue(letter,null),X=Convert.ToDouble(x.GetValue(start,null),CultureInfo.InvariantCulture),Y=yy,EndX=Convert.ToDouble(x.GetValue(finish,null),CultureInfo.InvariantCulture),Size=Convert.ToDouble(size.GetValue(letter,null),CultureInfo.InvariantCulture),Row=(int)Math.Round(yy/3.0),Order=order++});
        }
        records.Sort((a,b)=> {int row=b.Row.CompareTo(a.Row); if(row!=0)return row; int xx=a.X.CompareTo(b.X); return xx!=0?xx:a.Order.CompareTo(b.Order);});
        var text=new StringBuilder(); PositionedLetter previous=null;
        foreach(var letter in records)
        {
            if(previous!=null)
            {
                if(letter.Row!=previous.Row) text.Append('\n');
                else if(letter.X-previous.EndX>Math.Max(1.0,Math.Min(letter.Size,previous.Size)*0.2)) text.Append(' ');
            }
            text.Append(letter.Text); previous=letter;
        }
        return text.ToString();
    }
    public static MemoryStream CopyBounded(Stream input, long limit)
    {
        var output=new MemoryStream(); var buffer=new byte[65536];
        try {
            int count; while((count=input.Read(buffer,0,buffer.Length))>0) {
                if(output.Length>limit-count) throw new InvalidDataException("Expanded member limit.");
                output.Write(buffer,0,count);
            }
            output.Position=0; return output;
        } catch { output.Dispose(); throw; }
    }
    public static bool HasEncryptionMarker(Stream input)
    {
        long position=input.Position; var buffer=new byte[65536]; string tail="";
        try {
            int count; while((count=input.Read(buffer,0,buffer.Length))>0) {
                string chunk=tail+Encoding.ASCII.GetString(buffer,0,count);
                if(Regex.IsMatch(chunk,@"/Encrypt\b")) return true;
                tail=chunk.Substring(Math.Max(0,chunk.Length-32));
            }
            return false;
        } finally { input.Position=position; }
    }
}
