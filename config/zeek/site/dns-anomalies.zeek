module DNSAnomalies;

export {
    redef enum Notice::Type += { High_Entropy_Subdomain };
}

function shannon_entropy(s: string): double {
    local char_counts: table[string] of count;
    local len = |s|;
    if (len == 0) return 0.0;
    for (i in s) {
        local c = s[i];
        if (c in char_counts) char_counts[c] += 1;
        else char_counts[c] = 1;
    }
    local entropy = 0.0;
    for (c in char_counts) {
        local p = (char_counts[c] + 0.0) / len;
        entropy -= (p * (log2(p)));
    }
    return entropy;
}

event dns_request(c: connection, msg: dns_msg, query: string) {
    local parts = split_string(query, /\./);
    if (|parts| > 0) {
        local leftmost = parts[0];
        if (|leftmost| > 30 && shannon_entropy(leftmost) > 3.8) {
            NOTICE([$note=High_Entropy_Subdomain, $conn=c, $msg=fmt("High entropy subdomain: %s", query)]);
        }
    }
}
