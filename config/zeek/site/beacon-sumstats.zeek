module C2Beacon;

export {
    redef enum Notice::Type += { Beacon_Candidate };
}

event zeek_init() {
    local r1 = SumStats::Reducer($stream="beacon.bytes", $apply=set(SumStats::SUM, SumStats::STD_DEV, SumStats::AVERAGE));
    SumStats::create($name="c2-beaconing-1h",
                     $epoch=1hr,
                     $reducers=table(["beacon.bytes"] = r1),
                     $threshold=10.0,
                     $threshold_val(key: SumStats::Key, result: SumStats::Result): double = {
                         return result["beacon.bytes"]$num + 0.0;
                     },
                     $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
                         local res = result["beacon.bytes"];
                         local avg = res$average;
                         local std = res$std_dev;
                         if (avg > 0 && (std / avg) < 0.30) {
                             NOTICE([$note=Beacon_Candidate,
                                     $src=key$host,
                                     $msg=fmt("High probability beacon detected from %s", key$host)]);
                         }
                     });
}

event connection_state_remove(c: connection) {
    if (c$id$resp_p == 80/tcp || c$id$resp_p == 443/tcp || c$id$resp_p == 8443/tcp) {
        SumStats::observe("beacon.bytes", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=c$orig$size));
    }
}
