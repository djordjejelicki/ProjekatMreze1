using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;


namespace PacketProject.Server
{
    enum Proto { TCP, UDP }

    class Program
    {
        static readonly object consoleLock = new object();

        static void Main()
        {
            Console.Title = "Server";
            var proto = AskProtocol();
            var ip = AskIp("127.0.0.1");
            var port = AskPort(15001);
            if (proto == Proto.TCP) RunTcp(ip, port);
            else RunUdp(ip, port);
        }

        static Proto AskProtocol()
        {
            while (true)
            {
                Console.Write("Protokol [TCP/UDP]: ");
                var s = Console.ReadLine();
                if (s != null) s = s.Trim().ToUpperInvariant();
                if (s == "TCP") return Proto.TCP;
                if (s == "UDP") return Proto.UDP;
                Console.WriteLine("Unesi TCP ili UDP.");
            }
        }
        static IPAddress AskIp(string def)
        {
            while (true)
            {
                Console.Write("IP (Enter za " + def + "): ");
                var s = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(s)) s = def;
                IPAddress ?ip; if (IPAddress.TryParse(s, out ip)) return ip;
                Console.WriteLine("Nevažeća IP.");
            }
        }
        static int AskPort(int def)
        {
            while (true)
            {
                Console.Write("Port 1024–65535 (Enter za " + def + "): ");
                var s = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(s)) return def;
                int p; if (int.TryParse(s, out p) && p >= 1024 && p <= 65535) return p;
                Console.WriteLine("Nevažeći port.");
            }
        }

        // === TCP ===
        static void RunTcp(IPAddress ip, int port)
        {
            Socket? listener = null;
            var clients = new List<Socket>();
            var messages = new ConcurrentQueue<(Socket client, string msg)>();

            var liveClients = new ConcurrentDictionary<Socket, bool>(); 

            try
            {
                listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                listener.Bind(new IPEndPoint(ip, port));
                listener.Listen(10);  // backlog
                lock (consoleLock)
                {
                    Console.WriteLine("[TCP] Slušam na {0}:{1}", ip, port);
                }

                // Task za slanje odgovora
                Task.Run(() =>
                {
                    while (true)
                    {
                        if (messages.TryDequeue(out var item))
                        {
                            string? odgovor;
                            lock (consoleLock)
                            {
                                Console.Write($"Odgovor za klijenta {item.client.RemoteEndPoint}: ");
                                odgovor = Console.ReadLine();
                            }
                            byte[] outBuf = Encoding.UTF8.GetBytes(odgovor ?? "");

                            // šalji samo ako je klijent živ
                            if (liveClients.ContainsKey(item.client))
                            {
                                try
                                {
                                    item.client.Send(outBuf);
                                }
                                catch (Exception ex)
                                {
                                    lock (consoleLock)
                                    {
                                        Console.WriteLine($"[GREŠKA] Slanje poruke klijentu nije uspelo: {ex.Message}");
                                    }
                                }
                            }
                        }
                        Thread.Sleep(10);
                    }
                });

                while (true)
                {
                    // Poll listener za nove konekcije (neblokirajuće)
                    if (listener.Poll(1000, SelectMode.SelectRead))
                    {
                        try
                        {
                            var client = listener.Accept();
                            lock (consoleLock)
                            {
                                Console.WriteLine("Novi klijent: {0}", client.RemoteEndPoint);
                            }
                            clients.Add(client);
                            liveClients[client] = true; 
                        }
                        catch (SocketException ex)
                        {
                            lock (consoleLock)
                            {
                                Console.WriteLine($"[GREŠKA] Problem pri prihvatanju klijenta: {ex.Message}");
                            }
                        }
                    }

                    // Poll postojeće klijente
                    for (int i = clients.Count - 1; i >= 0; i--)
                    {
                        var c = clients[i];
                        try
                        {
                            if (c.Poll(1000, SelectMode.SelectRead))
                            {
                                var buf = new byte[4096];
                                int n = c.Receive(buf);
                                if (n == 0)
                                {
                                    lock (consoleLock)
                                    {
                                        Console.WriteLine("Klijent {0} je zatvorio vezu.", c.RemoteEndPoint);
                                    }
                                    liveClients.TryRemove(c, out _); 
                                    c.Close();
                                    clients.RemoveAt(i);
                                    continue;
                                }

                                string msg = Encoding.UTF8.GetString(buf, 0, n);
                                lock (consoleLock)
                                {
                                    Console.WriteLine("Primljeno od {0}: \"{1}\" ({2} B)", c.RemoteEndPoint, msg, n);
                                }
                                messages.Enqueue((c, msg));
                            }
                        }
                        catch (Exception ex)
                        {
                            lock (consoleLock)
                            {
                                Console.WriteLine($"[GREŠKA] Problem sa klijentom {c.RemoteEndPoint}: {ex.Message}");
                            }
                            liveClients.TryRemove(c, out _); 
                            c.Close();
                            clients.RemoveAt(i);
                        }
                    }

                    Thread.Sleep(10);
                }
            }
            catch (SocketException ex)
            {
                lock (consoleLock)
                {
                    Console.WriteLine("TCP greška: " + ex.Message);
                }
            }
            finally
            {
                foreach (var c in clients) c.Close();
                listener?.Close();
            }
        }

        // === UDP ===
        static void RunUdp(IPAddress ip, int port)
        {
            Socket? udp = null;
            var clients = new List<EndPoint>(); // lista poznatih pošiljalaca
            var messages = new ConcurrentQueue<(EndPoint sender, string msg)>();

            try
            {
                udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                udp.Bind(new IPEndPoint(ip, port));

                lock (consoleLock)
                {
                    Console.WriteLine("[UDP] Slušam na {0}:{1}", ip, port);
                }

                // Task za slanje odgovora
                Task.Run(() =>
                {
                    while (true)
                    {
                        if (messages.TryDequeue(out var item))
                        {
                            string? odgovor;
                            lock (consoleLock)
                            {
                                Console.Write($"Odgovor za klijenta {item.sender}: ");
                                odgovor = Console.ReadLine();
                            }

                            byte[] outBuf = Encoding.UTF8.GetBytes(odgovor ?? "");

                            // šalji paket
                            try
                            {
                                udp.SendTo(outBuf, item.sender);
                            }
                            catch (Exception ex)
                            {
                                lock (consoleLock)
                                {
                                    Console.WriteLine($"[GREŠKA] Slanje poruke klijentu {item.sender} nije uspelo: {ex.Message}");
                                }
                            }
                        }
                        Thread.Sleep(10);
                    }
                });

                var buf = new byte[4096];

                while (true)
                {
                    if (udp.Poll(1000, SelectMode.SelectRead))
                    {
                        EndPoint sender = new IPEndPoint(IPAddress.Any, 0);
                        int n = 0;

                        try
                        {
                            n = udp.ReceiveFrom(buf, ref sender);
                        }
                        catch (SocketException ex)
                        {
                            lock (consoleLock)
                            {
                                Console.WriteLine($"[GREŠKA] Problem pri prijemu: {ex.Message}");
                            }
                            continue;
                        }

                        string msg = Encoding.UTF8.GetString(buf, 0, n);
                        lock (consoleLock)
                        {
                            Console.WriteLine("Primljeno od {0}: \"{1}\" ({2} B)", sender, msg, n);
                        }

                        messages.Enqueue((sender, msg));

                        // ako je novi klijent, dodaj u listu
                        if (!clients.Contains(sender))
                        {
                            clients.Add(sender);
                        }
                    }

                    Thread.Sleep(10);
                }
            }
            catch (SocketException ex)
            {
                lock (consoleLock)
                {
                    Console.WriteLine("UDP greška: " + ex.Message);
                }
            }
            finally
            {
                udp?.Close();
            }
        }
    }
}