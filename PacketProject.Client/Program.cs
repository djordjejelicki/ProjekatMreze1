using System.Net;
using System.Net.Sockets;
using System.Text;

namespace PacketProject.Client
{
    enum Proto { TCP, UDP }

    class Program
    {
        static void Main()
        {
            Console.Title = "Client";
            var proto = AskProtocol();
            string ip = AskIp("127.0.0.1");
            int port = AskPort(15001);

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
        static string AskIp(string def)
        {
            Console.Write("IP servera (Enter za " + def + "): ");
            var s = Console.ReadLine();
            return string.IsNullOrWhiteSpace(s) ? def : s.Trim();
        }
        static int AskPort(int def)
        {
            while (true)
            {
                Console.Write("Port (Enter za " + def + "): ");
                var s = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(s)) return def;
                int p; if (int.TryParse(s, out p) && p >= 1024 && p <= 65535) return p;
                Console.WriteLine("Nevažeći port.");
            }
        }

        // === TCP: petlja slanja, očekuj echo ===
        static void RunTcp(string ip, int port)
        {
            Socket ?c = null;
            try
            {
                c = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                c.Connect(new IPEndPoint(IPAddress.Parse(ip), port));
                Console.WriteLine("Povezan na {0}:{1}", ip, port);

                while (true)
                {
                    Console.Write("Poruka (ENTER za kraj): ");
                    string ?msg = Console.ReadLine();
                    if (string.IsNullOrEmpty(msg)) break;

                    byte[] data = Encoding.UTF8.GetBytes(msg);
                    c.Send(data);

                    var buf = new byte[4096];
                    int n = c.Receive(buf);
                    if (n == 0) { Console.WriteLine("Server zatvorio vezu."); break; }
                    Console.WriteLine("Server: " + Encoding.UTF8.GetString(buf, 0, n));
                }
            }
            catch (SocketException ex) { Console.WriteLine("TCP greška: " + ex.Message); }
            finally
            {
                if (c != null) { try { c.Shutdown(SocketShutdown.Both); } catch { } c.Close(); }
            }
        }

        // === UDP: šalji na server, čitaj echo, petlja ===
        static void RunUdp(string ip, int port)
        {
            Socket ?udp = null;
            try
            {
                udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                EndPoint server = new IPEndPoint(IPAddress.Parse(ip), port);

                while (true)
                {
                    Console.Write("Poruka (ENTER za kraj): ");
                    string ?msg = Console.ReadLine();
                    if (string.IsNullOrEmpty(msg)) break;

                    byte[] data = Encoding.UTF8.GetBytes(msg);
                    udp.SendTo(data, server);

                    var buf = new byte[4096];
                    EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                    int n = udp.ReceiveFrom(buf, ref from);
                    Console.WriteLine("Server: " + Encoding.UTF8.GetString(buf, 0, n));
                }
            }
            catch (SocketException ex) { Console.WriteLine("UDP greška: " + ex.Message); }
            finally { if (udp != null) udp.Close(); }
        }
    }
}