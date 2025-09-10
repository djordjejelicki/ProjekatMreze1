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
                IPAddress ip; if (IPAddress.TryParse(s, out ip)) return ip;
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
            TcpListener listener = null;
            Socket sock = null;
            try
            {
                listener = new TcpListener(new IPEndPoint(ip, port));
                listener.Start();
                Console.WriteLine("[TCP] Slušam na {0}:{1}", ip, port);
                sock = listener.AcceptSocket();
                Console.WriteLine("Prihvaćena konekcija: {0} -> {1}",
                    (sock.RemoteEndPoint as IPEndPoint).ToString(),
                    (sock.LocalEndPoint as IPEndPoint).ToString());

                var buf = new byte[4096];
                while (true)
                {
                    int n = sock.Receive(buf);
                    if (n == 0) { Console.WriteLine("Klijent zatvorio vezu."); break; }
                    string msg = Encoding.UTF8.GetString(buf, 0, n);
                    Console.WriteLine("Primljeno: \"{0}\" ({1} B)", msg, n);

                    string reply = "Echo: " + msg;
                    byte[] outBuf = Encoding.UTF8.GetBytes(reply);
                    sock.Send(outBuf);
                }
            }
            catch (SocketException ex) { Console.WriteLine("TCP greška: " + ex.Message); }
            finally
            {
                try { if (sock != null) { sock.Shutdown(SocketShutdown.Both); sock.Close(); } } catch { }
                if (listener != null) listener.Stop();
            }
        }

        // === UDP: receive-from + echo nazad pošiljaocu ===
        static void RunUdp(IPAddress ip, int port)
        {
            Socket udp = null;
            try
            {
                udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                udp.Bind(new IPEndPoint(ip, port));
                Console.WriteLine("[UDP] Slušam na {0}:{1}", ip, port);

                var buf = new byte[4096];
                EndPoint sender = new IPEndPoint(IPAddress.Any, 0);

                while (true)
                {
                    int n = udp.ReceiveFrom(buf, ref sender);
                    string msg = Encoding.UTF8.GetString(buf, 0, n);
                    Console.WriteLine("Primljeno od {0}: \"{1}\"", sender, msg);

                    string reply = "Echo: " + msg;
                    byte[] outBuf = Encoding.UTF8.GetBytes(reply);
                    udp.SendTo(outBuf, sender);
                }
            }
            catch (SocketException ex) { Console.WriteLine("UDP greška: " + ex.Message); }
            finally { if (udp != null) udp.Close(); }
        }
    }
}