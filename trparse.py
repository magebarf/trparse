# -*- coding: utf-8 -*-

"""
Copyright (C) 2015 Luis Benitez

Parses the output of a traceroute execution into an AST (Abstract Syntax Tree).
"""

import re

STR_RE_HOSTNAME = r'[a-zA-z0-9\.-]+'
STR_RE_IPV4 = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
STR_RE_IPV6 = r'[0-9a-fA-F:]+'
STR_RE_FLOAT = r'\d+(?:\.?\d+)?'
STR_RE_IP = r'(?:{}|{})'.format(STR_RE_IPV4, STR_RE_IPV6)
STR_RE_NAME = r'(?:{}|{}|{})'.format(STR_RE_HOSTNAME, STR_RE_IPV4, STR_RE_IPV6)

RE_HEADER = re.compile(
        r'^traceroute to ({})\s+\(({})\), \d+ hops max, \d+ byte packets'.format(
            STR_RE_NAME, STR_RE_IP))
RE_HOP = re.compile(r'^\s*(\d+)\s+([\s\S]+?(?=^\s*\d+\s+|^_EOS_$))', re.M)
RE_PROBE_ASN = re.compile(r'^\[AS(\d+)\]$')
RE_PROBE_NAME = re.compile(r'^({})$'.format(STR_RE_NAME))
RE_PROBE_IP = re.compile(r'^\(({})\)$'.format(STR_RE_IP))
RE_PROBE_ONLY_IP = re.compile(r'^({})$'.format(STR_RE_IP))
RE_PROBE_RTT = re.compile(r'^({})$'.format(STR_RE_FLOAT))
RE_PROBE_ANNOTATION = re.compile(r'^(!\w*)$')
RE_PROBE_TIMEOUT = re.compile(r'^(\*)$')


class Traceroute(object):
    """
    Abstraction of a traceroute result.
    """
    def __init__(self, dest_name, dest_ip):
        self.dest_name = dest_name
        self.dest_ip = dest_ip
        self.hops = []

    def add_hop(self, hop):
        self.hops.append(hop)

    def __str__(self):
        text = "Traceroute for %s (%s)\n\n" % (self.dest_name, self.dest_ip)
        for hop in self.hops:
            text += str(hop)
        return text


class Hop(object):
    """
    Abstraction of a hop in a traceroute.
    """
    def __init__(self, idx):
        self.idx = idx # Hop count, starting at 1
        self.probes = [] # Series of Probe instances

    def add_probe(self, probe):
        """Adds a Probe instance to this hop's results."""
        self.probes.append(probe)

    def __str__(self):
        text = "{:>3d} ".format(self.idx)
        text_len = len(text)
        for n, probe in enumerate(self.probes):
            text_probe = str(probe)
            if n:
                text += (text_len*" ")+text_probe
            else:
                text += text_probe
        text += "\n"
        return text


class Probe(object):
    """
    Abstraction of a probe in a traceroute.
    """
    def __init__(self, asn=None, name=None, ip=None, rtt=None, anno=''):
        self.asn = asn # Autonomous System number
        self.name = name # Name (reverse DNS) (blank when using 'traceroute -n')
        self.ip = ip
        self.rtt = rtt # RTT in ms
        self.anno = anno # Annotation, such as '!H', '!N', '!X', etc

    def __str__(self):
        if self.rtt != None:
            text = ""
            if self.asn != None:
                text += "[AS{:d}] ".format(self.asn)
            if self.name:
                text += "{:s} ({:s}) ".format(self.name, self.ip)
            else:
                text += "{:s} ".format(self.ip)
            text += "{:1.3f} ms".format(self.rtt)
            if self.anno:
                text += " {:s}".format(self.anno)
            text += "\n"
        else:
            text = "*\n"
        return text


def loads(data):
    """Parser entry point. Parses the output of a traceroute execution"""
    data += "\n_EOS_" # Append EOS token. Helps to match last RE_HOP

    # Get headers
    match_dest = RE_HEADER.search(data)
    dest_name = match_dest.group(1)
    dest_ip = match_dest.group(2)

    # The Traceroute is the root of the tree.
    traceroute = Traceroute(dest_name, dest_ip)

    # Get hops
    matches_hop = RE_HOP.findall(data)

    for match_hop in matches_hop:
        # Initialize a hop
        idx = int(match_hop[0])
        hop = Hop(idx)

        # For each hop, iterate over its lines
        # Each line represents probes of the same host (asn/name/ip).
        for probes_line in match_hop[1].splitlines():
            asn = None
            name = None
            ip = None
            last_rtt = None
            next_check = 'timeout'

            # Split line into tokens: <[asn]> | <name> | <(ip)> | <rtt> | 'ms' | '*' | '!<anno>'
            probes_data = probes_line.split()
            # Get rid of 'ms'
            probes_data = filter(lambda s: s.lower() != 'ms', probes_data)

            # Parse tokens
            for token in probes_data:
                # Check initial timeout (optional)
                # Case which probe data starts with at least one timeout.
                if next_check == 'timeout':
                    match = RE_PROBE_TIMEOUT.match(token)
                    if match:
                        hop.add_probe(Probe())
                        continue
                    else:
                        next_check = 'asn'
                # Check ASN (optional)
                if next_check == 'asn':
                    next_check = 'name'
                    match = RE_PROBE_ASN.match(token)
                    if match:
                        asn = int(match.group(1))
                        continue
                # Check name
                if next_check == 'name':
                    next_check = 'ip'
                    name = RE_PROBE_NAME.match(token).group(1)
                    continue
                # Check IP (optional)
                if next_check == 'ip':
                    next_check = 'rtt'
                    match = RE_PROBE_IP.match(token)
                    if match:
                        ip = match.group(1)
                        continue
                    else:
                        # If not match IP, 'name' actually is the IP.
                        ip = RE_PROBE_ONLY_IP.match(name).group(1)
                        name = None
                # Check RTT (first RTT)
                if next_check == 'rtt':
                    match = RE_PROBE_TIMEOUT.match(token)
                    if match:
                        hop.add_probe(Probe())
                        continue
                    else:
                        next_check = 'rtt_or_anno'
                        last_rtt = float(RE_PROBE_RTT.match(token).group(1))
                        continue
                # Check RTT (new RTT) or annotation (to 'last_rtt')
                if next_check == 'rtt_or_anno':
                    match = RE_PROBE_TIMEOUT.match(token)
                    if match:
                        next_check = 'rtt'
                        if last_rtt:
                            hop.add_probe(Probe(asn, name, ip, last_rtt))
                            last_rtt = None
                        hop.add_probe(Probe())
                        continue
                    else:
                        match = RE_PROBE_ANNOTATION.match(token)
                        if match:
                            next_check = 'rtt'
                            anno = match.group(1)
                            hop.add_probe(Probe(asn, name, ip, last_rtt, anno))
                            last_rtt = None
                            continue
                        else:
                            if last_rtt:
                                hop.add_probe(Probe(asn, name, ip, last_rtt))
                            last_rtt = float(RE_PROBE_RTT.match(token).group(1))
                            continue
            # Process remaining RTT
            if last_rtt:
                 hop.add_probe(Probe(asn, name, ip, last_rtt))

        traceroute.add_hop(hop)

    return traceroute


def load(data):
    return loads(data.read())


class ParseError(Exception):
    pass
