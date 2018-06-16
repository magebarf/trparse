/*
Copyright (C) 2015 Luis Benitez
Copyright (C) 2018 Rarylson Freitas
Copyright (C) 2018 Patrik Thunström

Parses the output of a traceroute execution into an AST (Abstract Syntax Tree). */

function logit(stringToLog) {
    if (console && console.log) {
        console.log(stringToLog)
    }
}

// Set of regexes used for parsing
var re = {
    header : new RegExp('^traceroute to (\\S+)\\s+\\((?:(\\d+\\.\\d+\\.\\d+\\.\\d+)|([0-9a-fA-F:]+))\\)'),
    // _EOS_ is a string literal appended at the end of input before parsing
    hop : new RegExp('^\\s*(\\d+)\\s+([\\s\\S]+?(?=^\\s*\\d+\\s+|^_EOS_))', 'mg'), // Multiline and global
    probe : {
        asn : new RegExp('^\\[AS(\\d+)\\]$'),
        name : new RegExp('^([a-zA-z0-9\\.-]+)$|^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})$|^([0-9a-fA-F:]+)$'),
        ip : new RegExp('^\\((\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|[0-9a-fA-F:]+)\\)$'),
        rtt : new RegExp('^(\\d+(?:\\.?\\d+)?)$'),
        annotation : new RegExp('^(!\\w*)$'),
        timeout : new RegExp('^(\\*)$')
    }
}

function parse(data) {
    // Parser entry point. Parses the output of a traceroute execution
    data += "\n_EOS_" // Append EOS token. Helps to match last RE_HOP
    dataSplitlines = data.split(/\r?\n/)

    result = {}

    // Get header
    header_line = dataSplitlines[0]
    match_dest = header_line.match(re.header)
    if (match_dest) {
        dest_name = match_dest[1]
        dest_ip = match_dest[2]
    }
    else {
        logit("Parse error \n" + header_line)
        return
    }

    // The Traceroute is the root of the tree.
    result.dest_name = dest_name
    result.dest_ip = dest_ip
    result.hops = []


    var curHop

    // Get hops
    while ((curHop = re.hop.exec(data)) !== null) {
        // Initialize a hop
        console.log('Hop!')
        var hop = {}
        hop.probes = []
        hop.index = parseInt(curHop[1])

        var hopData = curHop[2].split(/\r?\n/)

        // For each hop parse probes
        // For this, iterate over all probe lines. Each line represents probes of the same
        // host (asn/name/ip).
        for (var i = 0; i < hopData.length; i++) {
            console.log('Probe!')
            var probe = {}
            // Split to separate strings
            var probeData = hopData[i].split(/\s+/)
            if (probeData.length === 1 && probeData[0] === "") {
                continue
            }

            // Probes data at this point: [<asn>] | <name> | <(IP)> | <rtt> | 'ms' | '*'
            // Get rid of 'ms': [<asn>] | <name> | <(IP)> | <rtt> | '*'
            probeData = probeData.filter(probeToken => probeToken.toLowerCase() !== 'ms')

            for (var j = 0; j < probeData.length; j++) {
                var regexResult
                // RTT check comes first because RE_PROBE_NAME can confuse rtt with an IP as name
                // The regex RE_PROBE_NAME can be improved
                if (regexResult = probeData[j].match(re.probe.rtt)) {
                    // Matched rtt, so asn, name and IP have been parsed before
                    if (!probe.rtt) {
                        probe.rtt = []
                    }
                    probe.rtt.push(parseFloat(probeData[j]))
                } else if (regexResult = probeData[j].match(re.probe.asn)) {
                    // Matched a ASN, so next elements is name
                    probe.asn = parseInt(regexResult[1])
                } else if (regexResult = probeData[j].match(re.probe.name)) {
                    // Matched a name, so next elements is expected to be an IP
                    var firstMatch = probeData[j]
                    // Match next for IP
                    if (regexResult = probeData[j + 1].match(re.probe.ip)) {
                        // IP found, skip one step in parsing
                        j++;
                        probe.name = firstMatch
                        probe.ip = regexResult[1]
                    } else {
                        // Next element is not an IP. So initially matched 'name' actually is the IP.
                        probe.ip = firstMatch
                    }
                } else if (regexResult = probeData[j].match(re.probe.timeout)) {
                    // Its a timeout, so maybe asn, name and IP have been parsed before
                    // or maybe not. But it's Hop job to deal with it.
                } else if (regexResult = probeData[j].match(re.probe.annotation)) {
                    probe.anno = probeData[j]
                }
            }

            hop.probes.push(probe)
        }

        result.hops.push(hop)
    }

    console.log(result)

    return result
}
