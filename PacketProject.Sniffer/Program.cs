using PacketDotNet;
using SharpPcap;
using System;
using System.Text;

namespace PacketProject.Sniffer
{
    class Program
    {
        static void Main()
        {
            Console.Title = "Packet Sniffer";

            // 1) Lista mrežnih interfejsa
            var devices = CaptureDeviceList.Instance;
            if (devices == null || devices.Count < 1)
            {
                Console.WriteLine("Nema mrežnih uređaja (proveri da li je Npcap instaliran).");
                return;
            }

            Console.WriteLine("=== Dostupni interfejsi ===");
            for (int i = 0; i < devices.Count; i++)
            {
                Console.WriteLine($"{i}) {devices[i].Description}");
            }

            Console.Write($"Izaberi interfejs (0-{devices.Count - 1}): ");
            int choice;
            if (!int.TryParse(Console.ReadLine(), out choice) || choice < 0 || choice >= devices.Count)
            {
                Console.WriteLine("Nevažeći izbor.");
                return;
            }

            var device = devices[choice];

            // 2) Otvaranje uređaja (SharpPcap v6+: DeviceConfiguration + DeviceModes)
            int readTimeoutMs = 1000;
            var config = new DeviceConfiguration
            {
                Mode = DeviceModes.Promiscuous,
                ReadTimeout = readTimeoutMs
            };

            try
            {
                device.Open(config);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Greška pri otvaranju uređaja: " + ex.Message);
                return;
            }

            // 3) BPF filter (opciono): npr. "tcp or udp", "port 15001", "tcp and port 15001"
            Console.Write("Unesi filter (Enter za sve): ");
            string filter = Console.ReadLine();
            if (!string.IsNullOrWhiteSpace(filter))
            {
                try
                {
                    device.Filter = filter;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Nevažeći filter: " + ex.Message);
                }
            }

            Console.WriteLine("Sniffer pokrenut. Pritisni ENTER za prekid...");

            // 4) Pretplata i start
            device.OnPacketArrival += OnPacketArrival;   // v6+ koristi PacketCapture u handleru
            device.StartCapture();

            Console.ReadLine();

            // 5) Stop i close
            try { device.StopCapture(); } catch { }
            try { device.Close(); } catch { }
        }

        // SharpPcap v6+ handler
        private static void OnPacketArrival(object sender, PacketCapture e)
        {
            var raw = e.GetPacket();
            var time = raw.Timeval.Date;
            int len = raw.Data.Length;

            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);

            //Ethernet sloj
            var eth = packet.Extract<EthernetPacket>();
            string macSrc = eth?.SourceHardwareAddress?.ToString() ?? "N/A";
            string macDst = eth?.DestinationHardwareAddress?.ToString() ?? "N/A";

            //IPv4 sloj
            var ip = packet.Extract<IPv4Packet>();
            string ipSrc = ip?.SourceAddress?.ToString() ?? "N/A";
            string ipDst = ip?.DestinationAddress?.ToString() ?? "N/A";


            string proto = "N/A";
            string extra = "";
            int srcPort = 0, dstPort = 0;

            if (ip is IPv4Packet ipv4)
            {
                proto = ipv4.Protocol.ToString();
                extra += $"  IPv4 Header: Len={ipv4.HeaderLength}, Id={ipv4.Id}, Checksum=0x{ipv4.Checksum:X4}\n";
            }

            //TCP sloj
            var tcp = packet.Extract<TcpPacket>();
            if (tcp != null)
            {
                proto = "TCP";
                srcPort = tcp.SourcePort;
                dstPort = tcp.DestinationPort;

                var flags = new StringBuilder();
                if (tcp.Synchronize) flags.Append("SYN ");
                if (tcp.Acknowledgment) flags.Append("ACK ");
                if (tcp.Finished) flags.Append("FIN ");
                if (tcp.Push) flags.Append("PSH ");
                if (tcp.Reset) flags.Append("RST ");
                if (tcp.Urgent) flags.Append("URG ");
                if (tcp.ExplicitCongestionNotificationEcho) flags.Append("ECE ");
                if (tcp.CongestionWindowReduced) flags.Append("CWR ");

                extra += $"  TCP: AckNum={tcp.AcknowledgmentNumber}, Flags={flags.ToString().Trim()}\n";
            }

            //UDP sloj
            var udp = packet.Extract<UdpPacket>();
            if (udp != null)
            {
                proto = "UDP";
                srcPort = udp.SourcePort;
                dstPort = udp.DestinationPort;
            }

            byte[] payload = tcp?.PayloadData ?? udp?.PayloadData;
            string payloadAscii = payload != null ? Encoding.ASCII.GetString(payload) : "";
            int payloadLen = payload?.Length ?? 0;

            //Ispis

            Console.WriteLine(new string('=', 60));
            Console.WriteLine($"{time:HH:mm:ss.fff} | Len={len}");
            Console.WriteLine($"MAC: {macSrc} -> {macDst}");
            Console.WriteLine($"IP:  {ipSrc}:{srcPort} -> {ipDst}:{dstPort} | Proto={proto}");
            if (!string.IsNullOrEmpty(extra)) Console.Write(extra);
            if (payloadLen > 0)
                Console.WriteLine($"Payload ({payloadLen} bytes): {payloadAscii}");
            Console.WriteLine(new string('-', 60));
        }
    }
}
