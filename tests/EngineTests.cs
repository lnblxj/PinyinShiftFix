using System;
using System.IO;
class EngineTests {
 static void Assert(bool ok,string s) {if(!ok)throw new Exception(s);Console.WriteLine("PASS "+s);}
 static void Reject(Action a,string s) {bool failed=false;try{a();}catch{failed=true;}Assert(failed,s);}
 static void Main(string[] args) { try { Run(args); } catch(Exception ex) {Console.WriteLine(ex.Message);Console.WriteLine(ex.StackTrace);Environment.ExitCode=1;} } static void Run(string[] args) {
 if(args.Length != 2) throw new Exception("Supply 2913 and 6456 sample directories (DLL + PDB)");
 string[] dirs=args;
 string[] hashes={"37681E754A3604177A47F71D0A22CC7C831FCEAB16D9C89E8A6B242053EE9313","19DEEFC96A97CECA3FF66570874920B2391837E491450100898C4448F56D2853"};
 for(int i=0;i<2;i++) {
 byte[] b=File.ReadAllBytes(dirs[i]+"/InputService.dll");string pdb=dirs[i]+"/InputService.pdb";
 var p=PatchEngine.Analyze(b,pdb);var patched=PatchEngine.Apply(b,p);
 Assert(p.PatchedHash==hashes[i],"symbol-derived exact expected patch "+i);
 var offline=PatchEngine.Analyze(b,null);Assert(offline.Offset==p.Offset && offline.PatchedHash==p.PatchedHash,"offline profile matches symbols "+i);
 var repeat=PatchEngine.Analyze(patched,pdb);Assert(repeat.OriginalHash==p.OriginalHash && repeat.PatchedHash==p.PatchedHash,"patched detection "+i);
 byte[] relocated=(byte[])b.Clone(); relocated[0x40]^=1;
 var unknown=PatchEngine.Analyze(relocated,pdb);Assert(unknown.OriginalHash!=p.OriginalHash && unknown.Offset==p.Offset,"non-whitelisted hash recognized by symbols "+i);
 byte[] bad=(byte[])b.Clone();bad[p.Offset-8]^=1;Reject(delegate{PatchEngine.Analyze(bad,pdb);},"corrupt table refused "+i);
 bad=(byte[])b.Clone();bad[p.Offset]^=1;Reject(delegate{PatchEngine.Analyze(bad,pdb);},"unexpected command refused "+i);
 Reject(delegate{PatchEngine.Analyze(b,dirs[1-i]+"/InputService.pdb");},"mismatched PDB refused "+i);
 Reject(delegate{PatchEngine.Apply(bad,p);},"changed input refused "+i);
 int changes=0;for(int j=0;j<b.Length;j++)if(b[j]!=patched[j])changes++;Assert(changes==4,"only four expected bytes changed "+i);
 }
 Reject(delegate{PatchEngine.Analyze(new byte[512],null);},"invalid PE refused");
 }
}

