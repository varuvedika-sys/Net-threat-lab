module TLSAnomalies;

export {
    redef enum Notice::Type += { Self_Signed_Non_Standard_Port, TLS_SNI_Certificate_Mismatch };
}

event ssl_established(c: connection) {
    if (!c$ssl?$cert_chain || |c$ssl$cert_chain| == 0) return;
    local cert = c$ssl$cert_chain[0]$x509$certificate;
    if (c$id$resp_p != 443/tcp && cert?$issuer && cert?$subject && cert$issuer == cert$subject) {
        NOTICE([$note=Self_Signed_Non_Standard_Port, $conn=c, $msg="Self-signed cert on non-standard port"]);
    }
    if (c$ssl?$server_name && cert?$subject && c$ssl$server_name !in cert$subject) {
        NOTICE([$note=TLS_SNI_Certificate_Mismatch, $conn=c, $msg="SNI mismatch"]);
    }
}
