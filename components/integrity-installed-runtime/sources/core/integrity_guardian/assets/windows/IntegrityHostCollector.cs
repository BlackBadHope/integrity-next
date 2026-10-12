using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace IntegrityGuardian
{
    internal static class IntegrityHostCollector
    {
        private static string Json(string value)
        {
            if (value == null) return "null";
            StringBuilder output = new StringBuilder();
            output.Append('"');
            foreach (char character in value)
            {
                switch (character)
                {
                    case '"': output.Append("\\\""); break;
                    case '\\': output.Append("\\\\"); break;
                    case '\b': output.Append("\\b"); break;
                    case '\f': output.Append("\\f"); break;
                    case '\n': output.Append("\\n"); break;
                    case '\r': output.Append("\\r"); break;
                    case '\t': output.Append("\\t"); break;
                    default:
                        if (character < 32)
                        {
                            output.Append("\\u");
                            output.Append(((int)character).ToString("x4"));
                        }
                        else output.Append(character);
                        break;
                }
            }
            output.Append('"');
            return output.ToString();
        }

        private static string JoinAddresses(IEnumerable<IPAddress> addresses)
        {
            List<string> values = new List<string>();
            foreach (IPAddress address in addresses) values.Add(address.ToString());
            values.Sort(StringComparer.Ordinal);
            return String.Join(",", values.ToArray());
        }

        private static string Fact(
            string kind,
            string identity,
            string layer,
            string metadata)
        {
            return "{\"subject_kind\":" + Json(kind)
                + ",\"identity\":" + Json(identity)
                + ",\"layer\":" + Json(layer)
                + ",\"state\":\"present\",\"content_digest\":null"
                + ",\"metadata\":{" + metadata + "}}";
        }

        private static string MetadataString(string key, string value)
        {
            return Json(key) + ":" + Json(value);
        }

        public static int Main(string[] args)
        {
            if (args.Length != 0) return 64;
            try
            {
                List<string> facts = new List<string>();
                string machine = Environment.MachineName;
                facts.Add(Fact(
                    "host",
                    "host:" + machine.ToLowerInvariant(),
                    "L0",
                    MetadataString("machine_name", machine) + ","
                    + MetadataString("os_version", Environment.OSVersion.VersionString) + ","
                    + "\"processor_count\":"
                    + Environment.ProcessorCount.ToString(CultureInfo.InvariantCulture) + ","
                    + "\"is_64_bit_os\":"
                    + (Environment.Is64BitOperatingSystem ? "true" : "false") + ","
                    + "\"read_only\":true"));

                foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
                {
                    IPInterfaceProperties properties = adapter.GetIPProperties();
                    List<IPAddress> unicast = new List<IPAddress>();
                    foreach (UnicastIPAddressInformation item in properties.UnicastAddresses)
                        unicast.Add(item.Address);
                    List<IPAddress> gateways = new List<IPAddress>();
                    foreach (GatewayIPAddressInformation item in properties.GatewayAddresses)
                        gateways.Add(item.Address);
                    List<IPAddress> dns = new List<IPAddress>();
                    foreach (IPAddress item in properties.DnsAddresses) dns.Add(item);
                    facts.Add(Fact(
                        "network-interface",
                        "network-interface:" + adapter.Id.ToLowerInvariant(),
                        "L0",
                        MetadataString("interface_name", adapter.Name) + ","
                        + MetadataString("interface_type", adapter.NetworkInterfaceType.ToString()) + ","
                        + MetadataString("operational_status", adapter.OperationalStatus.ToString()) + ","
                        + MetadataString("unicast_addresses", JoinAddresses(unicast)) + ","
                        + MetadataString("gateway_addresses", JoinAddresses(gateways)) + ","
                        + MetadataString("dns_addresses", JoinAddresses(dns)) + ","
                        + "\"read_only\":true"));
                    foreach (IPAddress gateway in gateways)
                    {
                        facts.Add(Fact(
                            "route",
                            "route:default:" + adapter.Id.ToLowerInvariant()
                                + ":" + gateway.ToString().ToLowerInvariant(),
                            "L1",
                            MetadataString("interface_name", adapter.Name) + ","
                            + MetadataString("gateway", gateway.ToString()) + ","
                            + "\"default_route\":true,\"read_only\":true"));
                    }
                }

                Console.OutputEncoding = new UTF8Encoding(false);
                Console.Write("{\"protocol\":\"integrity-guardian/collector-output/v1\","
                    + "\"observed_at\":"
                    + Json(DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture))
                    + ",\"facts\":[" + String.Join(",", facts.ToArray()) + "]}");
                return 0;
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine(exception.GetType().FullName);
                return 70;
            }
        }
    }
}
