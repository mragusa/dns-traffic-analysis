#!/usr/bin/env python3
# TODO
# Add client query output file
# Add server query output file
# Add % of success vs failures

import click
from tqdm import tqdm
from rich.console import Console
from rich.table import Table
from collections import defaultdict

# Disable scapy warnings
import logging

logging.getLogger("scapy").setLevel(logging.ERROR)
from scapy.all import (
    PcapReader,
    IP,
    IPv6,
    TCP,
    UDP,
    Dot1Q,
    DNS,
    DNSQR,
    DNSRR,
    UDPerror,
    TCPerror,
    ICMP,
    IPerror,
)

dns_clients = defaultdict(lambda: defaultdict(int))
dns_servers = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
network_vlan = defaultdict(int)
success_rate = defaultdict(int)
query_types = defaultdict(int)
op_codes = defaultdict(int)
notify_traffic = defaultdict(int)
icmp_client_errors = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
dns_client_icmp = []
# ICMP Information
icmp_type = {
    0: {0: "Echo Reply"},
    1: "Unassigned",
    2: "Unassigned",
    3: {
        0: "Destination network unreachable",
        1: "Destination host unreachable",
        2: "Destination protocol unreachable",
        3: "Destination port unreachable",
        4: "Fragmentation required, and DF flag set",
        5: "Source route failed",
        6: "Destination network unknown",
        7: "Destination host unknown",
        8: "Source host isolated",
        9: "Network administratively prohibited",
        10: "Host administratively prohibited",
        11: "Network unreachable for ToS",
        12: "Host unreachable for ToS",
        13: "Communication administratively prohibited",
        14: "Host Precedence Violation",
        15: "Precedence cutoff in effect",
    },
    4: {0: "Source quench (congestion control)"},
    5: {
        0: "Redirect Datagram for the Network",
        1: "Redirect Datagram for the Host",
        2: "Redirect Datagram for the ToS & network",
        3: "Redirect Datagram for the ToS & host",
    },
    6: "Alternate Host Address",
    7: "Unassigned",
    8: {0: "Echo Request"},
    9: {0: "Router Advertisement"},
    10: {0: "Router discovery/selection/solicitation"},
    11: {
        0: "Time to live (TTL) expired in transit",
        1: "Fragment reassembly time exceeded",
    },
    12: {
        0: "Pointer indicates the error",
        1: "Missing a required option",
        2: "Bad length",
    },
    13: {0: "Timestamp"},
    14: {0: "Timestamp reply"},
    15: {0: "Information Request"},
    16: {0: "Information Reply"},
    17: {0: "Address Mask Request"},
    18: {0: "Address Mask Reply"},
    19: "Reserved for security",
    20: "Reserved for robustness experiment",
    21: "Reserved for robustness experiment",
    22: "Reserved for robustness experiment",
    23: "Reserved for robustness experiment",
    24: "Reserved for robustness experiment",
    25: "Reserved for robustness experiment",
    26: "Reserved for robustness experiment",
    27: "Reserved for robustness experiment",
    28: "Reserved for robustness experiment",
    29: "Reserved for robustness experiment",
    30: {0: "Information Request"},
    31: "Datagram Conversion Error",
    32: "Mobile Host Redirect",
    33: "Where-Are-You (originally meant for IPv6)",
    34: "Here-I-Am (originally meant for IPv6)",
    35: "Mobile Registration Request",
    36: "Mobile Registration Reply",
    37: "Domain Name Request",
    38: "Domain Name Reply",
    39: "SKIP Algorithm Discovery Protocol, Simple Key-Management for Internet Protocol",
    40: "Photuris, Security failures",
    41: "ICMP for experimental mobility protocols such as Seamoby",
    42: {0: "Request Extended Echo"},
    43: {
        0: "No Error",
        1: "Malformed Query",
        2: "No Such Interface",
        3: "No Such Table Entry",
        4: "Multiple Interfaces Satisfy Query",
    },
    44: "Reserved",
    253: "RFC3692-style Experiment 1",
    254: "RFC3692-style Experiment 2",
    255: "Reserved",
}
# Op Code definitions
op_code_def = {0: "Query", 2: "Status", 4: "Notify", 5: "Update", 8: "NXDOMAIN"}
# Extended DNS RCodes
# https://developers.cloudflare.com/1.1.1.1/infrastructure/extended-dns-error-codes/
extended_rcodes = {
    1: "Unsupported DNSKEY Algorithm",
    2: "Unsupported DS Digest Type",
    3: "Stale Answer",
    6: "DNSSEC Bogus",
    7: "Signature Expired",
    8: "Signature Not Yet Valid",
    9: "DNSSEC Key Missing",
    10: "RRSIGs Missing",
    11: "No Zone Key Bit Set",
    12: "NSEC Missing",
    13: "Cached Error",
    22: "No Reachable Authority",
    23: "Network Error",
    30: "Invalid Query Type",
}
# DNS query type definitions
record_type_lookup = {
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
    4880: "OPENPGPKEY",
    704: "UNKNOWN-704",
    705: "MALFORMED",
    706: "DNSAPI",
    707: "ZONE EXISTS",
    3081: "UNKNOWN-3081",
    4109: "A6",
    3852: "UNKNOWN-3852",
    8482: "ANY-CLOUDFLARE",
}


@click.command()
@click.option("-f", "--file", help="Packet Capture File")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output for debugging")
@click.option(
    "-c", "--clients", is_flag=True, default=False, help="Display Client Data"
)
@click.option(
    "-s", "--servers", is_flag=True, default=False, help="Display Server Data"
)
@click.option("-r", "--report", is_flag=True, default=False, help="Summary Report")
def main(
    file: str,
    verbose: bool,
    clients: bool,
    servers: bool,
    report: bool,
):
    """Report on DNS Statistics in PCAP File"""
    console = Console()
    total_packets = 0
    print("Processing File: {}".format(file))
    with PcapReader(file) as packets:
        for _ in packets:
            total_packets += 1
    console.print(
        "[bold cyan]Total Packets Found: {}[/bold cyan]".format(total_packets)
    )
    with tqdm(
        total=total_packets, desc="Analyzing Capture", unit="packets", colour="blue"
    ) as pbar:
        with PcapReader(file) as packets:
            for packet in packets:
                process_packet(packet, verbose)
                pbar.update(1)
    if clients:
        for c in sorted(dns_clients):
            for q in dns_clients[c]:
                print(c, q, dns_clients[c][q])
    if servers:
        for s in sorted(dns_servers, key=lambda x: str(x)):
            for q in dns_servers[s]:
                for v in dns_servers[s][q]:
                    print(s, q, v, dns_servers[s][q][v])
    if report:
        display_report("Query Types", query_types)
        display_report("Op Codes", op_codes)
        display_report("Success Rates", success_rate)
        if notify_traffic:
            display_report("DNS Notifies", notify_traffic)
        else:
            print("DNS Notifies not detected in this capture")
        if network_vlan:
            display_report("VLANs", network_vlan)
        else:
            print("No VLANs detected in this capture")
        if icmp_client_errors:
            display_report("ICMP Errors", icmp_client_errors)
        else:
            print("Review Debug Output")


def process_packet(packet, verbose: bool):
    if verbose:
        print(packet)
    if UDP in packet or TCP in packet:
        dns = packet.getlayer(DNS)
        if dns is None or DNSQR not in dns:
            return
        if (
            Dot1Q in packet
            and IP in packet
            and (
                (UDP in packet and packet[UDP].dport == 53)
                or (TCP in packet and packet[TCP].dport == 53)
            )
        ):
            if verbose:
                print(
                    "DNS Client: {} Query: {} VLAN: {}".format(
                        packet[IP].src,
                        dns.qd.qname.decode("utf-8", errors="replace"),
                        packet[Dot1Q].vlan,
                    )
                )
            op_codes[packet[DNS].opcode] += 1
            if packet[DNS].opcode == 4:
                notify_traffic[packet[IP].src, "-", packet[IP].dst] += 1
            query_types[packet[DNS].qd.qtype] += 1
            network_vlan[packet[Dot1Q].vlan] += 1
            dns_clients[packet[IP].src][
                dns.qd.qname.decode("utf-8", errors="replace")
            ] += 1
        elif IP in packet and (
            (UDP in packet and packet[UDP].dport == 53)
            or (TCP in packet and packet[TCP].dport == 53)
        ):
            if verbose:
                print(
                    "DNS Client: {} Query: {}".format(
                        packet[IP].src, dns.qd.qname.decode("utf-8", errors="replace")
                    )
                )
            op_codes[packet[DNS].opcode] += 1
            if packet[DNS].opcode == 4:
                notify_traffic[packet[IP].src, "-", packet[IP].dst] += 1
            query_types[packet[DNS].qd.qtype] += 1
            dns_clients[packet[IP].src][
                dns.qd.qname.decode("utf-8", errors="replace")
            ] += 1
        elif (
            Dot1Q in packet
            and IPv6 in packet
            and (
                (UDP in packet and packet[UDP].dport == 53)
                or (TCP in packet and packet[TCP].dport == 53)
            )
        ):
            if verbose:
                print(
                    "DNS Client: {} Query: {}".format(
                        packet[IPv6].src, dns.qd.qname.decode("utf-8", errors="replace")
                    )
                )
            op_codes[packet[DNS].opcode] += 1
            if packet[DNS].opcode == 4:
                notify_traffic[packet[IPv6].src, "-", packet[IPv6].dst] += 1
            network_vlan[packet[Dot1Q].vlan] += 1
            query_types[packet[DNS].qd.qtype] += 1
            dns_clients[packet[IPv6].src][
                dns.qd.qname.decode("utf-8", errors="replace")
            ] += 1
        elif (IPv6 in packet and UDP in packet and packet[UDP].dport == 53) or (
            IPv6 in packet and TCP in packet and packet[TCP].dport == 53
        ):
            if verbose:
                print(
                    "DNS Client: {} Query: {}".format(
                        packet[IPv6].src, dns.qd.qname.decode("utf-8", errors="replace")
                    )
                )
            op_codes[packet[DNS].opcode] += 1
            if packet[DNS].opcode == 4:
                notify_traffic[packet[IPv6].src, "-", packet[IPv6].dst] += 1
            query_types[packet[DNS].qd.qtype] += 1
            dns_clients[packet[IPv6].src][
                dns.qd.qname.decode("utf-8", errors="replace")
            ] += 1
        elif (
            Dot1Q in packet
            and IP in packet
            and (
                (UDP in packet and packet[UDP].sport == 53)
                or (TCP in packet and packet[TCP].sport == 53)
            )
        ):
            if dns.an and verbose:
                print(
                    "DNS Server: {} Response: {} VLAN: {} RCode: {}".format(
                        packet[IP].src,
                        dns.an.rrname.decode("utf-8", errors="replace"),
                        packet[Dot1Q].vlan,
                        dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode),
                    )
                )
            if dns.an:
                op_codes[packet[DNS].opcode] += 1
                if packet[DNS].opcode == 4:
                    notify_traffic[packet[IP].src, "-", packet[IP].dst] += 1
                query_types[packet[DNS].qd.qtype] += 1
                network_vlan[packet[Dot1Q].vlan] += 1
                dns_servers[packet[IP].src][
                    dns.qd.qname.decode("utf-8", errors="replace")
                ][dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode)] += 1
                success_rate[
                    (dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode))
                ] += 1
        elif (IP in packet and UDP in packet and packet[UDP].sport == 53) or (
            IP in packet and TCP in packet and packet[TCP].sport == 53
        ):
            if dns.an and verbose:
                print(
                    "DNS Server: {} Response: {} RCode: {}".format(
                        packet[IP].src,
                        dns.an.rrname.decode("utf-8", errors="replace"),
                        dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode),
                    )
                )
            if dns.an:
                op_codes[packet[DNS].opcode] += 1
                if packet[DNS].opcode == 4:
                    notify_traffic[packet[IP].src, "-", packet[IP].dst] += 1
                query_types[packet[DNS].qd.qtype] += 1
                dns_servers[packet[IP].src][
                    dns.qd.qname.decode("utf-8", errors="replace")
                ][dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode)] += 1
                success_rate[
                    (dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode))
                ] += 1
        elif (
            Dot1Q in packet
            and IPv6 in packet
            and (
                (UDP in packet and packet[UDP].sport == 53)
                or (TCP in packet and packet[TCP].sport == 53)
            )
        ):
            if dns.an and verbose:
                print(
                    "DNS Server: {} Response: {} RCode: {}".format(
                        packet[IPv6].src,
                        dns.an.rrname.decode("utf-8", errors="replace"),
                        dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode),
                    )
                )
            if dns.an:
                op_codes[packet[DNS].opcode] += 1
                if packet[DNS].opcode == 4:
                    notify_traffic[packet[IP].src, "-", packet[IP].dst] += 1
                query_types[packet[DNS].qd.qtype] += 1
                network_vlan[packet[Dot1Q].vlan] += 1
                dns_servers[packet[IPv6].src][
                    dns.qd.qname.decode("utf-8", errors="replace")
                ][dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode)] += 1
                success_rate[
                    (dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode))
                ] += 1
        elif IPv6 in packet and (
            (UDP in packet and packet[UDP].sport == 53)
            or (TCP in packet and packet[TCP].sport == 53)
        ):
            if dns.an and verbose:
                print(
                    "DNS Server: {} Response: {} RCode: {}".format(
                        packet[IPv6].src,
                        dns.an.rrname.decode("utf-8", errors="replace"),
                        dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode),
                    )
                )
            if dns.an:
                op_codes[packet[DNS].opcode] += 1
                if packet[DNS].opcode == 4:
                    notify_traffic[packet[IP].src, "-", packet[IP].dst] += 1
                query_types[packet[DNS].qd.qtype] += 1
                dns_servers[packet[IPv6].src][
                    dns.qd.qname.decode("utf-8", errors="replace")
                ][dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode)] += 1
                success_rate[
                    (dns.get_field("rcode").i2s.get(dns.rcode, dns.rcode))
                ] += 1
        else:
            print("Unconsidered: {}".format(packet))
    if ICMP in packet:
        if (UDPerror in packet and packet[UDPerror].sport == 53) or (
            TCPerror in packet and packet[TCPerror].sport == 53
        ):
            if packet[ICMP].code:
                icmp_code = icmp_type[packet[ICMP].type][packet[ICMP].code]
            else:
                icmp_code = icmp_type[packet[ICMP].code]
            icmp_client_errors[packet[IPerror].src][packet[IPerror].dst][icmp_code] += 1


def display_report(report_name: str, data: dict):
    table = Table(title=report_name)
    if report_name == "Query Types":
        table.add_column("Type", justify="center")
        table.add_column("Count", justify="center")
        for qt in data:
            table.add_row(record_type_lookup[qt], str(data[qt]))
    if report_name == "Op Codes":
        table.add_column("Code", justify="center")
        table.add_column("Count", justify="center")
        for oc in data:
            table.add_row(op_code_def[oc], str(data[oc]))
    if report_name == "Success Rates":
        table.add_column("RCode", justify="center")
        table.add_column("Count", justify="center")
        for r in data:
            if r in extended_rcodes:
                table.add_row(extended_rcodes[r], str(data[r]))
            else:
                table.add_row(r, str(data[r]))
    if report_name == "DNS Notifies":
        table.add_column("SRC", justify="center")
        table.add_column("DST", justify="center")
        table.add_column("Count", justify="center")
        for n in data:
            table.add_row(n[0], n[2], str(data[n]))
    if report_name == "ICMP Errors":
        table.add_column("SRC", justify="center")
        table.add_column("DST", justify="center")
        table.add_column("Description", justify="center")
        table.add_column("Count", justify="center")
        for s in icmp_client_errors:
            if s in dns_clients.keys():
                for d in icmp_client_errors[s]:
                    for c in icmp_client_errors[s][d]:
                        table.add_row(s, d, c, str(icmp_client_errors[s][d][c]))
    if report_name == "VLANs":
        table.add_column("VLAN", justify="center")
        table.add_column("Count", justify="center")
        for v in data:
            table.add_row(str(v), str(data[v]))
    console = Console()
    console.print(table)


if __name__ == "__main__":
    main()
