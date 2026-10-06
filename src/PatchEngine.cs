using System;
using System.IO;
using System.Net;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

internal sealed class PatchPlan
{
    internal string OriginalHash, PatchedHash;
    internal int Offset;
    internal ulong Before, After;
}
internal static class PatchEngine
{
    internal static string Hash(byte[] b) { using(var s=SHA256.Create()) return BitConverter.ToString(s.ComputeHash(b)).Replace("-", ""); }
    static ushort U16(byte[] b,int o) { return BitConverter.ToUInt16(b,o); }
    static uint U32(byte[] b,int o) { return BitConverter.ToUInt32(b,o); }
    static ulong U64(byte[] b,int o) { return BitConverter.ToUInt64(b,o); }
    static void Check(bool ok,string reason) { if(!ok) throw new Exception("无法可靠识别补丁位置："+reason); }
    sealed class Pe
    {
        internal byte[] Data; internal int Opt, Sections, Count; internal ulong Base;
        internal Pe(byte[] b) {
            Data=b; Check(b.Length>256 && U16(b,0)==0x5a4d,"不是 PE 文件");
            int nt=checked((int)U32(b,60)); Check(nt>=64 && nt<b.Length-264,"PE 头越界");
            Check(U32(b,nt)==0x4550 && U16(b,nt+4)==0x8664,"只支持 AMD64 PE");
            Opt=nt+24; Check(U16(b,Opt)==0x20b && U16(b,nt+20)>=240,"可选头不支持");
            Base=U64(b,Opt+24); Count=U16(b,nt+6); Sections=Opt+U16(b,nt+20);
            Check(Count>0 && Sections+40L*Count<=b.Length,"节表越界");
        }
        internal int Offset(uint rva,int length) {
            for(int i=0;i<Count;i++) { int s=Sections+40*i; uint va=U32(Data,s+12),size=U32(Data,s+16),raw=U32(Data,s+20);
                if(rva>=va && (ulong)rva+ (uint)length<=(ulong)va+size) {
                    long o=(long)raw+rva-va; Check(o>=0 && o+length<=Data.Length,"节数据越界"); return (int)o;
                }
            } throw new Exception("RVA 不在文件节内。");
        }
        internal void ReadOnly(uint rva) {
            for(int i=0;i<Count;i++) {int s=Sections+40*i; uint va=U32(Data,s+12); if(rva>=va && (ulong)rva<(ulong)va+U32(Data,s+16)) {
                Check((U32(Data,s+36)&0xa0000000)==0,"目标必须是不可执行、不可写的数据节"); return;
            }} throw new Exception("目标节缺失。");
        }
        internal void Relocation(uint slot) {
            uint rva=U32(Data,Opt+112+5*8),size=U32(Data,Opt+116+5*8); int o=Offset(rva,checked((int)size)),end=checked(o+(int)size),matches=0;
            while(o<end) { Check(end-o>=8,"重定位块截断"); uint page=U32(Data,o),n=U32(Data,o+4); Check(n>=8 && n%2==0 && n<=end-o,"重定位块异常");
                for(int k=o+8;k<o+n;k+=2) {ushort v=U16(Data,k); if(page+(v&4095)==slot) {Check((v>>12)==10,"目标不是 DIR64 重定位"); matches++;}}
                o+=checked((int)n);
            } Check(matches==1,"目标重定位不唯一");
        }
    }
    internal static byte[] Apply(byte[] original,PatchPlan p) {
        Check(Hash(original)==p.OriginalHash,"原文件哈希改变"); byte[] b=(byte[])original.Clone();
        Check(U64(b,p.Offset)==p.Before,"原命令指针改变"); Array.Copy(BitConverter.GetBytes(p.After),0,b,p.Offset,8); Checksum(b);
        Check(Hash(b)==p.PatchedHash,"生成结果哈希不匹配"); return b;
    }
    static void Checksum(byte[] b) {
        int o=checked((int)U32(b,60))+88; Array.Clear(b,o,4); ulong sum=0;
        for(int i=0;i<b.Length;i+=2) {sum+=(uint)b[i]+(i+1<b.Length?(uint)b[i+1]<<8:0);sum=(sum&65535)+(sum>>16);}
        sum=(sum&65535)+(sum>>16); Array.Copy(BitConverter.GetBytes((uint)(sum+(ulong)b.Length)),0,b,o,4);
    }
    internal static PatchPlan Analyze(byte[] b,string pdbPath) {
        var pe=new Pe(b); string h=Hash(b); uint table=0,toggle=0,insert=0;
        // Exact known files can work offline. All other files use matching public symbols.
        if(pdbPath==null && (h=="EE32A592C481A01049A618DA1941C6512E5DBA4C326DACA134F9E64472AB0D32" || h=="37681E754A3604177A47F71D0A22CC7C831FCEAB16D9C89E8A6B242053EE9313")) { table=0x355bc0;toggle=0x374340;insert=0x373290; }
        else if(pdbPath==null && (h=="9E2D850C844E15E5960209F7E4A4C81B4A84FE157684012D8D423A595015F4B9" || h=="19DEEFC96A97CECA3FF66570874920B2391837E491450100898C4448F56D2853")) {table=0x364370;toggle=0x382b50;insert=0x381a30;}
        else {
            byte[] guid=null; uint age=0; uint dr=U32(b,pe.Opt+112+6*8),ds=U32(b,pe.Opt+116+6*8);
            Check(ds>=28 && ds%28==0,"缺少调试目录"); int d=pe.Offset(dr,checked((int)ds));
            for(int k=d;k<d+ds;k+=28) if(U32(b,k+12)==2) {int cv=pe.Offset(U32(b,k+20),checked((int)U32(b,k+16))); if(U32(b,cv)!=0x53445352)continue;
                Check(guid==null && U32(b,k+16)>=25,"RSDS 标识异常"); guid=new byte[16];Array.Copy(b,cv+4,guid,0,16);age=U32(b,cv+20);
                int end=Array.IndexOf(b,(byte)0,cv+24,checked((int)U32(b,k+16))-24); Check(end>=0,"PDB 名称截断");
                Check(Path.GetFileName(Encoding.ASCII.GetString(b,cv+24,end-cv-24)).Equals("InputService.pdb",StringComparison.OrdinalIgnoreCase),"PDB 名称不匹配");
            }
            Check(guid!=null,"缺少 RSDS 标识"); byte[] pdb;
            if(pdbPath!=null) pdb=File.ReadAllBytes(pdbPath);
            else {string id=new Guid(guid).ToString("N").ToUpperInvariant()+age.ToString("X");
                ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
                using(var web=new WebClient()) pdb=web.DownloadData("https://msdl.microsoft.com/download/symbols/InputService.pdb/"+id+"/InputService.pdb");
            }
            var streams=ReadPdb(pdb); Check(streams.Count>3 && streams[1].Length>=28,"PDB 信息缺失");
            Check(U32(streams[1],8)>=age,"PDB age 不匹配"); for(int i=0;i<16;i++)Check(streams[1][12+i]==guid[i],"PDB GUID 不匹配");
            byte[] dbi=streams[3]; Check(dbi.Length>=64,"DBI 截断"); Check(U32(dbi,8)==age,"DBI age 不匹配"); int sym=U16(dbi,20); Check(sym<streams.Count,"符号流索引错误");
            byte[] records=streams[sym]; var found=new Dictionary<string,uint>();
            for(int o=0;o<records.Length;) {Check(records.Length-o>=4,"符号记录截断");int n=U16(records,o)+2; Check(n>=4 && n<=records.Length-o,"符号记录长度异常");
                if(U16(records,o+2)==0x110e && n>=15) {int end=Array.IndexOf(records,(byte)0,o+14,n-14);Check(end>=0,"符号名截断");string name=Encoding.ASCII.GetString(records,o+14,end-o-14);
                    if(name=="?cmds_HwKbdDn_Pinyin_Shift@ChxIME@@3QBUVKeyCommandEntry@1@B" || name=="ImeCommandID_ToggleShape" || name=="ImeCommandID_InsertSymbol") {
                        int seg=U16(records,o+12);Check(seg>0 && seg<=pe.Count,"符号节错误");uint r=checked(U32(b,pe.Sections+40*(seg-1)+12)+U32(records,o+8));Check(!found.ContainsKey(name),"符号不唯一");found.Add(name,r);
                    }
                } o+=n;
            }
            Check(found.Count==3,"所需的三个公开符号不齐全");table=found["?cmds_HwKbdDn_Pinyin_Shift@ChxIME@@3QBUVKeyCommandEntry@1@B"];toggle=found["ImeCommandID_ToggleShape"];insert=found["ImeCommandID_InsertSymbol"];
        }
        pe.ReadOnly(table);pe.ReadOnly(toggle);pe.ReadOnly(insert);pe.Relocation(table+8);
        int t=pe.Offset(table,24),a=pe.Offset(toggle,16),z=pe.Offset(insert,16);
        Check(BitConverter.ToString(b,a,16).Replace("-","")=="DB61C6E17A3DC04FB09A94036132FB65","ToggleShape 命令内容变化");
        Check(BitConverter.ToString(b,z,16).Replace("-","")=="2C2A80EF9C111D4D85DAC00836478F4C","InsertSymbol 命令内容变化");
        Check(U64(b,t)==0x200020 && U64(b,t+16)==2,"Shift 表首条记录结构变化");
        ulong before=checked(pe.Base+toggle),after=checked(pe.Base+insert);Check(U64(b,t+8)==before || U64(b,t+8)==after,"表中的命令指针不匹配");
        byte[] original=(byte[])b.Clone(),patched=(byte[])b.Clone();
        if(U64(b,t+8)==after) {Array.Copy(BitConverter.GetBytes(before),0,original,t+8,8);Checksum(original);}
        Array.Copy(BitConverter.GetBytes(after),0,patched,t+8,8);Checksum(patched);
        return new PatchPlan {OriginalHash=Hash(original),PatchedHash=Hash(patched),Offset=t+8,Before=before,After=after};
    }
    static List<byte[]> ReadPdb(byte[] b) {
        Check(b.Length>=56 && Encoding.ASCII.GetString(b,0,32).StartsWith("Microsoft C/C++ MSF 7.00\r\n",StringComparison.Ordinal),"PDB 格式不支持");
        int bs=checked((int)U32(b,32)),size=checked((int)U32(b,44)); Check(bs>=512 && bs<=65536 && size>0 && size<=b.Length,"PDB 目录异常");
        int map=checked((int)U32(b,52)*bs),count=(size+bs-1)/bs;Check(count*4<=bs && map>=0 && map+(long)count*4<=b.Length,"PDB 目录映射越界");
        byte[] dir=Blocks(b,b,map,size,bs);int n=checked((int)U32(dir,0)); Check(n>3 && 4L+4L*n<=dir.Length,"PDB 流数量异常");int pos=4+4*n;var result=new List<byte[]>();
        for(int i=0;i<n;i++) {uint s=U32(dir,4+4*i);if(s==uint.MaxValue) {result.Add(new byte[0]);continue;}Check(s<=b.Length,"PDB 流过大");result.Add(Blocks(b,dir,pos,(int)s,bs));pos=checked(pos+((int)s+bs-1)/bs*4);}
        return result;
    }
    static byte[] Blocks(byte[] b,byte[] index,int pos,int size,int bs) {
        byte[] output=new byte[size];for(int done=0;done<size;done+=bs) {Check(pos>=0 && pos<=index.Length-4,"PDB 块表越界");long src=(long)U32(index,pos)*bs;pos+=4;int n=Math.Min(bs,size-done);Check(src>=0 && src+n<=b.Length,"PDB 块越界");Array.Copy(b,src,output,done,n);}return output;
    }
}


