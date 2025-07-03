#!/usr/bin/env python3 -O

import argparse
import statistics
import cProfile
from tqdm import tqdm
import logging

# Disable warning messages on startup
logging.getLogger("scapy").setLevel(logging.ERROR)
from scapy.all import IP, IPv6, UDP, DNS, DNSQR, DNSRR, PcapReader


class DnsAnalyzer:
    def __init__(
        self,
        capture_file,
        source_ip,
        time_delay,
        output_file,
        report_file,
        verbose=False,
    ):
        self.capture_file = capture_file
        self.source_ip = source_ip.strip()
        self.time_delay = time_delay
        self.verbose = verbose
        self.queries_received = []
        self.responses_sent = []
        self.recordname = {}
        self.recordname_id = {}
        self.recordtypes = {}
        self.latency_times = []
        self.slow_queries = []
        self.record_type_lookup = {
            1: "A",
            28: "AAAA",
            62: "CSYNC",
            49: "DHCID",
            32769: "DLV",
            39: "DNAME",
            48: "DNSKEY",
            43: "DS",
            108: "EUI48",
            109: "EUI64",
            13: "HINFO",
            55: "HIP",
            65: "HTTPS",
            45: "IPSECKEY",
            25: "KEY",
            36: "KX",
            29: "LOC",
            15: "MX",
            35: "NAPTR",
            2: "NS",
            47: "NSEC",
            50: "NSEC3",
            51: "NSEC3PARAM",
            61: "OPENPGPKEY",
            12: "PTR",
            17: "RP",
            46: "RRSIG",
            24: "SIG",
            53: "SMIMEA",
            6: "SOA",
            33: "SRV",
            44: "SSHFP",
            64: "SVCB",
            32768: "TA",
            249: "TKEY",
            52: "TLSA",
            250: "TSIG",
            16: "TXT",
            256: "URI",
            63: "ZONEMD",
            255: "*",
            252: "AXFR",
            251: "IXFR",
            41: "OPT",
            3: "MD",
            4: "MF",
            254: "MAILA",
            7: "MB",
            8: "MG",
            9: "MR",
            14: "MINFO",
            253: "MAILB",
            11: "WKS",
            32: "NB",
            10: "NULL",
            38: "A6",
            30: "NXT",
            19: "X25",
            20: "ISDN",
            21: "RT",
            22: "NSAP",
            23: "NSAP-PTR",
            26: "PX",
            31: "EID",
            34: "ATMA",
            40: "SINK",
            27: "GPOS",
            100: "UINFO",
            101: "UID",
            102: "GID",
            103: "UNSPEC",
            99: "SPF",
            56: "NINFO",
            57: "RKEY",
            58: "TALINK",
            104: "NID",
            105: "L32",
            106: "L64",
            107: "LP",
            259: "DOA",
            18: "AFSDB",
            42: "APL",
            257: "CAA",
            60: "CDNSKEY",
            59: "CDS",
            37: "CERT",
            5: "CNAME",
        }
        self.file = output_file
        self.report = report_file

    def process_packet(self, packet):
        if self.verbose:
            print(packet)
        if DNS in packet and (
            (
                IP in packet
                and (
                    packet[IP].dst == self.source_ip or packet[IP].src == self.source_ip
                )
            )
            or (
                IPv6 in packet
                and (
                    packet[IPv6].dst == self.source_ip
                    or packet[IPv6].src == self.source_ip
                )
            )
        ):
            dns = packet.getlayer(DNS)
            if self.verbose:
                print(dns)  # Corrected indentation
            if dns is not None:
                if DNSQR in dns:
                    if (IP in packet and (packet[IP].dst == self.source_ip)) or (
                        IPv6 in packet and (packet[IPv6].dst == self.source_ip)
                    ):
                        self.queries_received.append(
                            {
                                "query_id": dns.id,
                                "query_request": dns.qd.qname,
                                "query_time": packet.time,
                            }
                        )
                        if dns.qd.qtype not in self.recordtypes:
                            self.recordtypes[dns.qd.qtype] = 1
                        else:
                            self.recordtypes[dns.qd.qtype] += 1

                        if dns.qd.qname not in self.recordname:
                            self.recordname[dns.qd.qname] = 1
                            self.recordname_id[dns.qd.qname] = [dns.id]
                        else:
                            self.recordname[dns.qd.qname] += 1
                            self.recordname_id[dns.qd.qname].append(dns.id)
                    if (IP in packet and (packet[IP].src == self.source_ip)) or (
                        IPv6 in packet and (packet[IPv6].src == self.source_ip)
                    ):
                        if isinstance(dns.an, DNSRR):
                            response_name = dns.an.rrname
                            self.responses_sent.append(
                                {
                                    "query_id": dns.id,
                                    "response_time": packet.time,
                                    "rrname": response_name,
                                }
                            )
                            if self.verbose:
                                print(
                                    "{}{}{}".format(dns.id, dns.qd.qname, packet.time)
                                )
                        elif isinstance(dns.an, list):
                            for response in dns.an:
                                response_name = response.rrname
                                self.responses_sent.append(
                                    {
                                        "query_id": dns.id,
                                        "response_time": packet.time,
                                        "rrname": response_name,
                                    }
                                )
                                if self.verbose:
                                    print(
                                        "{}{}{}".format(
                                            dns.id, packet.time, response_name
                                        )
                                    )

    def process_latency(self, query):
        if self.verbose:
            print("Query: {}".format(query))
        query_id = query["query_id"]
        query_match = next(
            (resp for resp in self.responses_sent if resp["query_id"] == query_id),
            None,
        )
        if self.verbose:
            print("Query Match: {}".format(query_match))
        if query_match:
            latency_time = query_match["response_time"] - query["query_time"]
            if self.verbose:
                print("Query ID: {}, Latency Time: {}".format(query_id, latency_time))
            self.latency_times.append(latency_time)
            if latency_time > self.time_delay:
                self.slow_queries.append(
                    {
                        "query": query["query_request"],
                        "query_id": query_id,
                        "latency": latency_time,
                    }
                )
                if self.verbose:
                    print("Slow query appended")

    def analyze(self):
        total_packets = 0

        with PcapReader(self.capture_file) as packets:
            for _ in packets:
                total_packets += 1

        print(
            "\033[94mTotal packets found {} in {}\033[0m".format(
                total_packets, self.capture_file
            )
        )
        print()
        # Add the tqdm progress bar to the loop
        with tqdm(
            total=total_packets,
            desc="Processing packets",
            unit="packets",
            colour="blue",
        ) as pbar:
            with PcapReader(self.capture_file) as packets:
                for packet in packets:
                    self.process_packet(packet)
                    pbar.update(1)  # Update the progress bar

        print()
        print(
            "\033[94mNumber of queries received: {}\033[0m".format(
                len(self.queries_received)
            )
        )
        print(
            "\033[94mNumber of responses sent: {}\033[0m".format(
                len(self.responses_sent)
            )
        )
        print()

        with tqdm(
            total=len(self.queries_received),
            desc="Processing Query Latency",
            unit="queries",
            colour="green",
        ) as pbar:
            for query in self.queries_received:
                self.process_latency(query)
                pbar.update(1)
        print()
        print(
            "\033[94mTotal Slow Queries\033[0m: \033[93m{}\033[0m".format(
                len(self.slow_queries)
            )
        )
        print("\033[92mSaving slow queries to file\033[0m")
        with open(self.file, "w") as f:
            for query in self.slow_queries:
                f.write(str(query) + "\n")
        print()
        print("\033[95mProcessing Latency Times\033[0m")
        print()
        if self.latency_times:
            lowest_latency = min(self.latency_times)
            highest_latency = max(self.latency_times)
            median_latency = statistics.median(self.latency_times)
            # Calculate Mean (need to optimize this later)
            total_sum = sum(self.latency_times)
            count = len(self.latency_times)
            mean_latency = total_sum / count

            print("\033[94mLowest Latency: {}\033[0m".format(lowest_latency))
            print("\033[91mHighest Latency: {}\033[0m".format(highest_latency))
            print("\033[93mMedian Latency: {}\033[0m".format(median_latency))
            print("\033[92mMean Latency: {}\033[0m".format(mean_latency))

        total = total_packets
        slow = len(self.slow_queries)
        percentage_difference = ((total - slow) / total) * 100
        print()
        print("\033[94mTotal Packets: {}\033[0m".format(total))
        print("\033[91mSlow Queries: {}\033[0m".format(slow))
        print("\033[94mPercentage Difference: {}%\033[0m".format(percentage_difference))
        print()
        sorted_recordname = sorted(
            self.recordname.items(), key=lambda x: x[1], reverse=True
        )
        print("\033[92mSaving Total Names Queried Report\033[0m")
        print()
        if self.verbose:
            for i in sorted_recordname:
                print("Query and Count: {}".format(i))
        with open(self.report, "w") as f:
            for query, count in sorted_recordname:
                f.write(
                    "Query: {} Count: {} Query ID: {}\n".format(
                        query, count, self.recordname_id[query]
                    )
                )

        print("\033[94mTotal Record Types Queried\033[0m")
        for i in self.recordtypes:
            print(
                "\033[94mType:\033[0m {} \033[96mCount:\033[0m {}".format(
                    self.record_type_lookup[i], self.recordtypes[i]
                )
            )


def main():
    parser = argparse.ArgumentParser(
        description="Script to parse traffic capture files for slow queries",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="This script will read a valid pcap file created by tcpdump and begin analysis to determine what DNS queries are slower that the provided timing (default 0.5 seconds aka 500ms. Upon analysis, the output of all slow queries will be saved to a file in the following format query, query_id, latency. Wireshark can be used with the following filter: dns.id==<query_id> to filter the existing packet capture file to only show the latent query in question. If a tcpdump file is too large and the desire is to break up the file into smaller segments for faster processing, the following command can be used: tcpdump -r <packet_capture> -w <new_file> -C <size> example: tcpdump -r traffic.cap -w slow_queries -C 100. Processing ttime varies but a 100MB file takes about 10 mins",
    )
    parser.add_argument("-f", "--file", help="Traffic Capture File")
    parser.add_argument("-s", "--source", help="DNS Server IP Address")
    parser.add_argument(
        "-t", "--time", help="Latency delay measured in seconds", default=0.5
    )
    parser.add_argument(
        "-r",
        "--report",
        help="Query Traffic Report Count",
        default="query_traffic_count.txt",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Name of slow queries file output",
        default="slow_queries.txt",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    analyzer = DnsAnalyzer(
        args.file, args.source, float(args.time), args.output, args.report, args.verbose
    )
    analyzer.analyze()


if __debug__:
    # Run the script without -O to enable the cProfile debug mode
    print("cProfile Enabled")
    cProfile.run("main()")
else:
    if __name__ == "__main__":
        main()
