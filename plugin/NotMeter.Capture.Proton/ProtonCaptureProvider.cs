using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using Not4You.Meter.Capture;

namespace NotMeter.Capture.Proton;

/// <summary>
/// Entry point that NotMeter looks for in Plugins/Proton when it runs under Wine
/// with NOTMETER_PROTON_CAPTURE=1.
/// </summary>
public sealed class ProtonCaptureProviderPlugin : ICaptureProviderPlugin
{
    public int ApiVersion => 1;

    public string Id => "proton";

    public IPacketCaptureProvider Create(CaptureProviderContext context)
    {
        return new ProtonCaptureProvider(context);
    }
}

/// <summary>
/// Reads packets captured on the Linux side by notmeter-capture.py and hands
/// them to the meter the same way the built-in Npcap provider does:
/// inbound TCP payloads go to TcpPayloadCaptured, outbound ones only signal
/// OutboundGamePayloadCaptured.
/// </summary>
public sealed class ProtonCaptureProvider : IPacketCaptureProvider, ICaptureDiagnosticsSource
{
    private const int DefaultHelperPort = 47380;
    private const string DeviceName = "Linux (notmeter-capture)";

    private readonly CaptureProviderContext _context;
    private readonly object _gate = new object();
    private Thread? _thread;
    private CancellationTokenSource? _cts;
    private TcpClient? _client;
    private bool _disposed;

    private long _records;
    private long _bytes;
    private long _inbound;
    private long _outbound;
    private long _emptyPayload;
    private long _parseErrors;
    private string _stage = "idle";
    private string _errorType = string.Empty;

    public ProtonCaptureProvider(CaptureProviderContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public string Id => "proton";

    public event EventHandler<CapturedTcpPayload>? TcpPayloadCaptured;

    public event Action<DateTimeOffset>? OutboundGamePayloadCaptured;

    public event EventHandler<CaptureStatusChangedEventArgs>? StatusChanged;

    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        lock (_gate)
        {
            if (_thread != null)
            {
                return;
            }
            _cts = new CancellationTokenSource();
            CancellationToken token = _cts.Token;
            _thread = new Thread(() => Run(token))
            {
                IsBackground = true,
                Name = "NotMeter Proton capture"
            };
            _thread.Start();
        }
    }

    public void Stop()
    {
        Thread? thread;
        lock (_gate)
        {
            thread = _thread;
            _thread = null;
            _cts?.Cancel();
            try
            {
                _client?.Close();
            }
            catch
            {
            }
        }
        if (thread != null && thread != Thread.CurrentThread)
        {
            thread.Join(TimeSpan.FromSeconds(3));
        }
        lock (_gate)
        {
            _cts?.Dispose();
            _cts = null;
        }
        _stage = "stopped";
    }

    public void ResetSessionState(string reason)
    {
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        Stop();
        _disposed = true;
        TcpPayloadCaptured = null;
        OutboundGamePayloadCaptured = null;
        StatusChanged = null;
    }

    public CaptureDiagnosticsSnapshot GetCaptureDiagnostics()
    {
        return new CaptureDiagnosticsSnapshot(_stage, _errorType, 0, 228u,
            Interlocked.Read(ref _records), Interlocked.Read(ref _bytes),
            Interlocked.Read(ref _inbound), Interlocked.Read(ref _outbound),
            0, Interlocked.Read(ref _emptyPayload), 0, Interlocked.Read(ref _parseErrors));
    }

    private void Run(CancellationToken token)
    {
        int helperPort = ReadIntEnv("NOTMETER_HELPER_PORT", DefaultHelperPort);
        int gamePort = ReadIntEnv("NOTMETER_GAME_PORT", _context.Options.ServerPort ?? 0);
        if (gamePort < 0 || gamePort > 65535)
        {
            gamePort = 0;
        }
        bool reportedWaiting = false;

        while (!token.IsCancellationRequested)
        {
            try
            {
                _stage = "connect";
                using TcpClient client = new TcpClient(AddressFamily.InterNetwork);
                client.NoDelay = true;
                client.ReceiveBufferSize = 4 * 1024 * 1024;
                lock (_gate)
                {
                    _client = client;
                }
                client.Connect(IPAddress.Loopback, helperPort);
                NetworkStream stream = client.GetStream();

                byte[] hello = Encoding.ASCII.GetBytes($"NOTMETER1 port={gamePort}\n");
                stream.Write(hello, 0, hello.Length);
                string reply = ReadLine(stream);
                if (!reply.StartsWith("OK", StringComparison.Ordinal))
                {
                    throw new IOException("notmeter-capture: " + reply);
                }

                reportedWaiting = false;
                _stage = "running";
                _errorType = string.Empty;
                RaiseStatus("running", "게임 패킷 사용 중: " + DeviceName);
                ReadRecords(new BufferedStream(stream, 1 << 20), token);
                if (!token.IsCancellationRequested)
                {
                    throw new IOException("notmeter-capture closed the connection");
                }
            }
            catch (Exception ex) when (!token.IsCancellationRequested)
            {
                _stage = "waiting-helper";
                _errorType = ex.GetType().Name;
                if (!reportedWaiting)
                {
                    reportedWaiting = true;
                    RaiseStatus("error",
                        "Linux capture helper (notmeter-capture) is not reachable on 127.0.0.1:" + helperPort +
                        ". Start it with: sudo systemctl start notmeter-capture. (" + ex.Message + ")");
                }
            }
            catch
            {
                // Stopping.
            }
            finally
            {
                lock (_gate)
                {
                    _client = null;
                }
            }

            if (token.WaitHandle.WaitOne(TimeSpan.FromSeconds(2)))
            {
                break;
            }
        }
    }

    private void ReadRecords(Stream stream, CancellationToken token)
    {
        byte[] header = new byte[11];
        byte[] packet = new byte[65536];
        while (!token.IsCancellationRequested)
        {
            if (!ReadExact(stream, header, 11))
            {
                return;
            }
            byte direction = header[0];
            uint seconds = ReadU32(header, 1);
            uint micros = ReadU32(header, 5);
            int length = (header[9] << 8) | header[10];
            if (!ReadExact(stream, packet, length))
            {
                return;
            }
            Interlocked.Increment(ref _records);
            Interlocked.Add(ref _bytes, length);
            DateTimeOffset arrivedAt = DateTimeOffset.FromUnixTimeSeconds(seconds).AddTicks(micros * 10L);
            try
            {
                Dispatch(direction, packet, length, arrivedAt);
            }
            catch
            {
                Interlocked.Increment(ref _parseErrors);
            }
        }
    }

    private void Dispatch(byte direction, byte[] p, int length, DateTimeOffset arrivedAt)
    {
        if (length < 40 || (p[0] >> 4) != 4 || p[9] != 6)
        {
            Interlocked.Increment(ref _parseErrors);
            return;
        }
        int ipHeader = (p[0] & 0x0F) * 4;
        int total = Math.Min(length, (p[2] << 8) | p[3]);
        if (ipHeader < 20 || total < ipHeader + 20)
        {
            Interlocked.Increment(ref _parseErrors);
            return;
        }
        int tcpHeader = (p[ipHeader + 12] >> 4) * 4;
        int payloadOffset = ipHeader + tcpHeader;
        int payloadLength = total - payloadOffset;
        if (tcpHeader < 20 || payloadLength <= 0)
        {
            Interlocked.Increment(ref _emptyPayload);
            return;
        }

        if (direction == 1)
        {
            Interlocked.Increment(ref _outbound);
            OutboundGamePayloadCaptured?.Invoke(arrivedAt);
            return;
        }

        Interlocked.Increment(ref _inbound);
        IPAddress source = new IPAddress(new ReadOnlySpan<byte>(p, 12, 4));
        IPAddress destination = new IPAddress(new ReadOnlySpan<byte>(p, 16, 4));
        int sourcePort = (p[ipHeader] << 8) | p[ipHeader + 1];
        int destinationPort = (p[ipHeader + 2] << 8) | p[ipHeader + 3];
        uint sequence = ReadU32(p, ipHeader + 4);
        byte[] payload = new byte[payloadLength];
        Buffer.BlockCopy(p, payloadOffset, payload, 0, payloadLength);

        TcpPayloadCaptured?.Invoke(this, new CapturedTcpPayload(
            source, destination, sourcePort, destinationPort, sequence, payload, arrivedAt, DeviceName));
    }

    private void RaiseStatus(string status, string message)
    {
        try
        {
            StatusChanged?.Invoke(this, new CaptureStatusChangedEventArgs(status, message));
        }
        catch
        {
        }
    }

    private static string ReadLine(Stream stream)
    {
        StringBuilder sb = new StringBuilder();
        while (sb.Length < 512)
        {
            int b = stream.ReadByte();
            if (b < 0 || b == '\n')
            {
                break;
            }
            sb.Append((char)b);
        }
        return sb.ToString().Trim();
    }

    private static bool ReadExact(Stream stream, byte[] buffer, int count)
    {
        int read = 0;
        while (read < count)
        {
            int n = stream.Read(buffer, read, count - read);
            if (n <= 0)
            {
                return false;
            }
            read += n;
        }
        return true;
    }

    private static uint ReadU32(byte[] b, int offset)
    {
        return (uint)((b[offset] << 24) | (b[offset + 1] << 16) | (b[offset + 2] << 8) | b[offset + 3]);
    }

    private static int ReadIntEnv(string name, int fallback)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        return int.TryParse(value, out int parsed) ? parsed : fallback;
    }
}
