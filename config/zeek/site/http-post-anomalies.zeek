module HTTPPostAnomalies;

export {
    redef enum Notice::Type += { Malleable_C2_URI_Match };
    const c2_uris: set[string] = { "/api/v1/update", "/submit.php", "/match/default" } &redef;
}

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (is_orig && c$http?$method && c$http$method == "POST" && c$http?$uri && c$http$uri in c2_uris) {
        NOTICE([$note=Malleable_C2_URI_Match, $conn=c, $msg=fmt("C2 URI matched: %s", c$http$uri)]);
    }
}
