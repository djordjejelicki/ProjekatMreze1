using System.Net;
using System.Net.Sockets;
using System.Text;


namespace PacketProject.Server
{
    enum Proto { TCP, UDP }

    class Program
    {
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

        // === TCP: prihvati jednog klijenta, echo petlja ===
        static void RunTcp(IPAddress ip, int port)
        {
            Socket ?listener = null;
            var clients = new List<Socket>();

            try
            {
                listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                listener.Bind(new IPEndPoint(ip, port));
                listener.Listen(10);  // backlog
                Console.WriteLine("[TCP] Slušam na {0}:{1}", ip, port);

                while (true)
                {
                    // Poll listener za nove konekcije (neblokirajuće)
                    if (listener.Poll(1000, SelectMode.SelectRead))
                    {
                        var client = listener.Accept();
                        Console.WriteLine("Novi klijent: {0}", client.RemoteEndPoint);
                        clients.Add(client);
                    }

                    // Poll postojeće klijente
                    for (int i = clients.Count - 1; i >= 0; i--)
                    {
                        var c = clients[i];
                        if (c.Poll(1000, SelectMode.SelectRead))
                        {
                            var buf = new byte[4096];
                            int n = c.Receive(buf);
                            if (n == 0)
                            {
                                Console.WriteLine("Klijent {0} je zatvorio vezu.", c.RemoteEndPoint);
                                c.Close();
                                clients.RemoveAt(i);
                                continue;
                            }

                            string msg = Encoding.UTF8.GetString(buf, 0, n);
                            Console.WriteLine("Primljeno od {0}: \"{1}\" ({2} B)", c.RemoteEndPoint, msg, n);

                            // Echo nazad
                            byte[] outBuf = Encoding.UTF8.GetBytes("Echo: " + msg);
                            c.Send(outBuf);
                        }
                    }

                    // Mala pauza da CPU ne gori
                    System.Threading.Thread.Sleep(10);
                }
            }
            catch (SocketException ex)
            {
                Console.WriteLine("TCP greška: " + ex.Message);
            }
            finally
            {
                foreach (var c in clients) c.Close();
                listener?.Close();
            }
        }

        // === UDP: receive-from + echo nazad pošiljaocu ===
        static void RunUdp(IPAddress ip, int port)
        {
            Socket ?udp = null;
            var clients = new List<EndPoint>(); // lista poznatih pošiljalaca

            try
            {
                udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                udp.Bind(new IPEndPoint(ip, port));
                Console.WriteLine("[UDP] Slušam na {0}:{1}", ip, port);

                var buf = new byte[4096];

                while (true)
                {
                    // Poll UDP soket za spremne podatke
                    if (udp.Poll(1000, SelectMode.SelectRead))
                    {
                        EndPoint sender = new IPEndPoint(IPAddress.Any, 0);
                        int n = udp.ReceiveFrom(buf, ref sender);

                        string msg = Encoding.UTF8.GetString(buf, 0, n);
                        Console.WriteLine("Primljeno od {0}: \"{1}\" ({2} B)", sender, msg, n);

                        // Ako je novi klijent, dodaj u listu
                        if (!clients.Contains(sender)) clients.Add(sender);

                        // Echo nazad
                        byte[] outBuf = Encoding.UTF8.GetBytes("Echo: " + msg);
                        udp.SendTo(outBuf, sender);
                    }

                    // Mala pauza da CPU ne gori
                    System.Threading.Thread.Sleep(10);
                }
            }
            catch (SocketException ex)
            {
                Console.WriteLine("UDP greška: " + ex.Message);
            }
            finally
            {
                udp?.Close();
            }
        }
    }
}