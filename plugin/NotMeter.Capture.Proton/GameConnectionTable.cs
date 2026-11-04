using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace NotMeter.Capture.Proton;

/// <summary>
/// IPv4 TCP connections of the Aion2 process, read through Wine's
/// GetExtendedTcpTable (the same source NotMeter uses to recognise game packets).
///
/// Used to map packets of a proxied connection back to the game's own socket.
/// With a TUN-mode proxy such as Throne the game talks to the proxy
/// (e.g. 10.254.20.123:42126 -> server:13328) while the proxy opens its own
/// connection from the real interface (192.168.10.7:54922 -> server:13328).
/// The byte stream is the same, only our side of the address differs, and
/// NotMeter drops packets whose addresses don't match the game's socket.
/// </summary>
internal sealed class GameConnectionTable
{
    internal readonly record struct Connection(IPAddress LocalAddress, int LocalPort, IPAddress RemoteAddress, int RemotePort);

    private const int AfInet = 2;
    private const int TcpTableOwnerPidAll = 5;
    private const uint StateEstablished = 5;
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(1);

    private readonly object _gate = new object();
    private DateTime _refreshedAt = DateTime.MinValue;
    private HashSet<Connection> _exact = new HashSet<Connection>();
    private Dictionary<(IPAddress, int), List<Connection>> _byRemote = new Dictionary<(IPAddress, int), List<Connection>>();

    // Game connections whose own packets were captured: those need no mapping.
    private readonly Dictionary<Connection, DateTime> _seenDirectly = new Dictionary<Connection, DateTime>();

    private readonly Func<List<Connection>> _read;

    internal GameConnectionTable(Func<List<Connection>>? read = null)
    {
        _read = read ?? ReadGameConnections;
    }

    /// <summary>
    /// Returns the game connection an inbound packet belongs to, or null when
    /// the packet already matches a game socket or no single game connection fits.
    /// </summary>
    internal Connection? MapInbound(IPAddress source, int sourcePort, IPAddress destination, int destinationPort)
    {
        lock (_gate)
        {
            Refresh();
            DateTime now = DateTime.UtcNow;
            Connection direct = new Connection(destination, destinationPort, source, sourcePort);
            if (_exact.Contains(direct))
            {
                _seenDirectly[direct] = now;
                return null;
            }
            if (!_byRemote.TryGetValue((source, sourcePort), out List<Connection>? candidates) || candidates.Count != 1)
            {
                return null;
            }
            Connection game = candidates[0];
            if (_seenDirectly.TryGetValue(game, out DateTime seen) && now - seen < TimeSpan.FromSeconds(10))
            {
                // The game's own leg is visible; mapping the proxy leg too would duplicate data.
                return null;
            }
            return game;
        }
    }

    private void Refresh()
    {
        DateTime now = DateTime.UtcNow;
        if (now - _refreshedAt < RefreshInterval)
        {
            return;
        }
        _refreshedAt = now;
        try
        {
            HashSet<Connection> exact = new HashSet<Connection>();
            Dictionary<(IPAddress, int), List<Connection>> byRemote = new Dictionary<(IPAddress, int), List<Connection>>();
            {
                foreach (Connection c in _read())
                {
                    exact.Add(c);
                    if (!byRemote.TryGetValue((c.RemoteAddress, c.RemotePort), out List<Connection>? list))
                    {
                        byRemote[(c.RemoteAddress, c.RemotePort)] = list = new List<Connection>();
                    }
                    list.Add(c);
                }
            }
            _exact = exact;
            _byRemote = byRemote;
            List<Connection> stale = new List<Connection>();
            foreach (Connection c in _seenDirectly.Keys)
            {
                if (!exact.Contains(c))
                {
                    stale.Add(c);
                }
            }
            foreach (Connection c in stale)
            {
                _seenDirectly.Remove(c);
            }
        }
        catch
        {
            // Keep the previous table.
        }
    }

    private static List<Connection> ReadGameConnections()
    {
        HashSet<uint> pids = GamePids();
        return pids.Count == 0 ? new List<Connection>() : ReadTable(pids);
    }

    private static HashSet<uint> GamePids()
    {
        HashSet<uint> pids = new HashSet<uint>();
        foreach (Process process in Process.GetProcessesByName("Aion2"))
        {
            using (process)
            {
                pids.Add((uint)process.Id);
            }
        }
        return pids;
    }

    private static List<Connection> ReadTable(HashSet<uint> pids)
    {
        List<Connection> result = new List<Connection>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
        if (size <= 0)
        {
            return result;
        }
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableOwnerPidAll, 0) != 0)
            {
                return result;
            }
            int count = Marshal.ReadInt32(buffer);
            // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid.
            for (int i = 0; i < count; i++)
            {
                int row = 4 + i * 24;
                uint state = (uint)Marshal.ReadInt32(buffer, row);
                uint pid = (uint)Marshal.ReadInt32(buffer, row + 20);
                if (state != StateEstablished || !pids.Contains(pid))
                {
                    continue;
                }
                IPAddress local = new IPAddress((uint)Marshal.ReadInt32(buffer, row + 4));
                IPAddress remote = new IPAddress((uint)Marshal.ReadInt32(buffer, row + 12));
                int localPort = Port(Marshal.ReadInt32(buffer, row + 8));
                int remotePort = Port(Marshal.ReadInt32(buffer, row + 16));
                if (remotePort == 0 || IPAddress.IsLoopback(remote))
                {
                    continue;
                }
                result.Add(new Connection(local, localPort, remote, remotePort));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return result;
    }

    // Ports are stored in network byte order in the low 16 bits.
    private static int Port(int raw)
    {
        return ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int ipVersion, int tableClass, int reserved);
}
