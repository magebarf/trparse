"""
Copyright (C) 2015 Luis Benitez
Copyright (C) 2018 Rarylson Freitas

Parses the output of a traceroute execution into an AST (Abstract Syntax Tree).
"""
RE_HEADER = re.compile(r'^traceroute to (\S+)\s+\((?:(\d+\.\d+\.\d+\.\d+)|([0-9a-fA-F:]+))\)')
RE_HOP = re.compile(r'^\s*(\d+)\s+([\s\S]+?(?=^\s*\d+\s+|^_EOS_))', re.M)

RE_PROBE_ASN = re.compile(r'^\[AS(\d+)\]$')
RE_PROBE_NAME = re.compile(r'^([a-zA-z0-9\.-]+)$|^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$|^([0-9a-fA-F:]+)$')
RE_PROBE_IP = re.compile(r'^\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+)\)$')
RE_PROBE_RTT = re.compile(r'^(\d+(?:\.?\d+)?)$')
RE_PROBE_ANNOTATION = re.compile(r'^(!\w*)$')
RE_PROBE_TIMEOUT = re.compile(r'^(\*)$')

def loads(data):
    """Parser entry point. Parses the output of a traceroute execution"""
    data += "\n_EOS_" # Append EOS token. Helps to match last RE_HOP

    # Get header
    header_line = data.splitlines()[0]
    match_dest = RE_HEADER.match(header_line)
    if match_dest:
        dest_name = match_dest.group(1)
        dest_ip = match_dest.group(2)
    else:
        ext = "header_line: {0:s}".format(header_line)
        raise ParseError("Parse error \n{0:s}".format(ext))

    # The Traceroute is the root of the tree.
    traceroute = Traceroute(dest_name, dest_ip)

    # Get hops
    matches_hop = RE_HOP.findall(data)

    for match_hop in matches_hop:
        # Initialize a hop
        idx = int(match_hop[0])
        hop = Hop(idx)

        # For each hop parse probes
        # For this, iterate over all probe lines. Each line represents probes of the same
        # host (asn/name/ip).
        for probes_line in match_hop[1].splitlines():
            asn = None
            name = None
            ip = None

            # Parse probes data: [<asn>] | <name> | <(IP)> | <rtt> | 'ms' | '*'
            probes_data = probes_line.split()
            # Get rid of 'ms': [<asn>] | <name> | <(IP)> | <rtt> | '*'
            probes_data = list(filter(lambda s: s.lower() != 'ms', probes_data))

            i = 0
            while i < len(probes_data):
                rtt = None
                anno = ''

                # RTT check comes first because RE_PROBE_NAME can confuse rtt with an IP as name
                # The regex RE_PROBE_NAME can be improved
                if RE_PROBE_RTT.match(probes_data[i]):
                    # Matched rtt, so asn, name and IP have been parsed before
                    rtt = float(probes_data[i])
                    i += 1
                elif RE_PROBE_ASN.match(probes_data[i]):
                    # Matched a ASN, so next elements is name
                    asn = int(RE_PROBE_ASN.match(probes_data[i]).group(1))
                    print(asn)
                    i += 1
                    continue
                elif RE_PROBE_NAME.match(probes_data[i]):
                    # Matched a name, so next elements is expected to be an IP
                    name = probes_data[i]
                    i += 1
                    if RE_PROBE_IP.match(probes_data[i]):
                        ip = RE_PROBE_IP.match(probes_data[i]).group(1)
                        i += 1
                    else:
                        # Next element is not an IP. So 'name' actually is the IP.
                        ip = name
                        name = None
                    continue
                elif RE_PROBE_TIMEOUT.match(probes_data[i]):
                    # Its a timeout, so maybe asn, name and IP have been parsed before
                    # or maybe not. But it's Hop job to deal with it.
                    i += 1
                else:
                    ext = "i: {0:d}\nprobes_data: {1:s}\nasn: {2:s}\nname: {3:s}\nip: {4:s}\nrtt: {5:s}\nanno: {6:s}".format(
                            i, probes_data, asn, name, ip, rtt, anno)
                    raise ParseError("Parse error \n{0:s}".format(ext))
                # Check for annotation
                try:
                    if RE_PROBE_ANNOTATION.match(probes_data[i]):
                        anno = probes_data[i]
                        i += 1
                except IndexError:
                    pass

                probe = Probe(asn, name, ip, rtt, anno)
                hop.add_probe(probe)

        traceroute.add_hop(hop)

    return traceroute


def load(data):
    return loads(data.read())


class ParseError(Exception):
    pass
