using PacketDotNet;
using SharpPcap;
using System;
using System.Text;

namespace PacketProject.Sniffer
{
    class Program
    {
        // =========================
        // ZADATAK 9 — STATISTIKA
        // Globalni akumulatori za praćenje najvećeg payload-a i ukupnog payload-a
        // =========================
        static long totalPayloadBytes = 0;           // zbir dužina svih aplikativnih delova (payload) koje smo presreli
        static int packetOrdinal = 0;                // redni broj paketa (od starta sniffera)

        static int maxPayloadBytes = -1;             // najveća do sada viđena dužina payload-a
        static int maxPacketOrdinal = -1;            // redni broj paketa sa najvećim payload-om
        static DateTime maxTimestamp = DateTime.MinValue; // vreme hvatanja tog paketa
        static string maxSrcIp = "";                 // izvorna IP adresa paketa sa najvećim payload-om
        static int maxSrcPort = -1;                  // izvorni port paketa sa najvećim payload-om

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

            // 5) Stop, ispiši statistiku, pa close
            try { device.StopCapture(); } catch { }

            // >>> ZADATAK 9 — Ispis statistike pri gašenju sniffera <<<
            PrintStatistics();

            Console.WriteLine("Pritisni ENTER da zatvoriš sniffer...");
            Console.ReadLine();

            try { device.Close(); } catch { }
        }

        // Izdvojena funkcija da bi ispis bio uredan i jasno odvojen
        private static void PrintStatistics()
        {
            Console.WriteLine();
            Console.WriteLine("=== STATISTIKA (Zadatak 9) ===");

            if (maxPayloadBytes >= 0 && totalPayloadBytes > 0)
            {
                double procenat = 100.0 * maxPayloadBytes / totalPayloadBytes;
                Console.WriteLine($"Najveći payload je imao paket #{maxPacketOrdinal}");
                Console.WriteLine($"Vreme: {maxTimestamp:yyyy-MM-dd HH:mm:ss.fff}");
                Console.WriteLine($"Izvor: {maxSrcIp}:{maxSrcPort}");
                Console.WriteLine($"Dužina aplikativnog dela: {maxPayloadBytes} B");
                Console.WriteLine($"Udeo u ukupnom payload-u: {procenat:F2}% ( {maxPayloadBytes} / {totalPayloadBytes} )");
            }
            else
            {
                Console.WriteLine("Nije bilo aplikativnog payload-a u presretnutim paketima.");
            }

            Console.WriteLine("=== KRAJ STATISTIKE ===");
            Console.WriteLine();
        }

        // SharpPcap v6+ handler
        private static void OnPacketArrival(object sender, PacketCapture e)
        {
            var raw = e.GetPacket();
            var time = raw.Timeval.Date;             // vreme hvatanja ovog paketa (koristimo ga i za statistiku)
            int len = raw.Data.Length;

            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);

            // Ethernet sloj
            var eth = packet.Extract<EthernetPacket>();
            string macSrc = eth?.SourceHardwareAddress?.ToString() ?? "N/A";
            string macDst = eth?.DestinationHardwareAddress?.ToString() ?? "N/A";

            // IPv4 sloj
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

            // TCP sloj
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

            // UDP sloj
            var udp = packet.Extract<UdpPacket>();
            if (udp != null)
            {
                proto = "UDP";
                srcPort = udp.SourcePort;
                dstPort = udp.DestinationPort;
            }

            // APLIKATIVNI DEO (payload) — zajednički za TCP/UDP
            byte[] payload = tcp?.PayloadData ?? udp?.PayloadData;
            string payloadAscii = payload != null ? Encoding.ASCII.GetString(payload) : "";
            int payloadLen = payload?.Length ?? 0;

            // Ispis osnovnih podataka o paketu
            Console.WriteLine(new string('=', 60));
            Console.WriteLine($"{time:HH:mm:ss.fff} | Len={len}");
            Console.WriteLine($"MAC: {macSrc} -> {macDst}");
            Console.WriteLine($"IP:  {ipSrc}:{srcPort} -> {ipDst}:{dstPort} | Proto={proto}");
            if (!string.IsNullOrEmpty(extra)) Console.Write(extra);
            if (payloadLen > 0)
                Console.WriteLine($"Payload ({payloadLen} bytes): {payloadAscii}");
            Console.WriteLine(new string('-', 60));

            // =========================
            // ZADATAK 9 — AŽURIRANJE STATISTIKE
            // =========================

            // 1) Uvećaj redni broj paketa
            packetOrdinal++;

            // 2) Saberi ukupni payload preko svih paketa
            totalPayloadBytes += payloadLen;

            // 3) Ako je ovo najveći payload do sada, zapamti sve tražene podatke
            if (payloadLen > maxPayloadBytes)
            {
                maxPayloadBytes = payloadLen;
                maxPacketOrdinal = packetOrdinal;
                maxTimestamp = time;        // vreme preuzimamo iz samog paketa
                maxSrcIp = ipSrc;
                maxSrcPort = srcPort;
            }
        }
    }
}
