using System;
using PacketDotNet;
using SharpPcap;

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
            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);

            var eth = packet.Extract<EthernetPacket>();
            var ip = packet.Extract<IPv4Packet>();
            var tcp = packet.Extract<TcpPacket>();
            var udp = packet.Extract<UdpPacket>();

            string macSrc = eth?.SourceHardwareAddress?.ToString() ?? "N/A";
            string macDst = eth?.DestinationHardwareAddress?.ToString() ?? "N/A";
            string ipSrc = ip?.SourceAddress?.ToString() ?? "N/A";
            string ipDst = ip?.DestinationAddress?.ToString() ?? "N/A";

            string srcPort = tcp != null ? tcp.SourcePort.ToString() : udp != null ? udp.SourcePort.ToString() : "-";
            string dstPort = tcp != null ? tcp.DestinationPort.ToString() : udp != null ? udp.DestinationPort.ToString() : "-";

            string protocol = tcp != null ? "TCP" : udp != null ? "UDP" : "Other";

            Console.WriteLine("======================================");
            Console.WriteLine($"MAC: {macSrc} -> {macDst}");
            Console.WriteLine($"IP:  {ipSrc}:{srcPort} -> {ipDst}:{dstPort} | Proto={protocol}");
        }
    }
}
