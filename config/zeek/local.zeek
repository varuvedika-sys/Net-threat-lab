@load protocols/conn
@load protocols/dns
@load protocols/http
@load protocols/ssl
@load protocols/files
@load protocols/x509
@load frameworks/notice
@load frameworks/software
@load frameworks/intel

redef LogAscii::use_json = T;
@load ja3
redef Intel::read_files += { "/lab/intel/intel.dat" };

@load ./site/beacon-sumstats.zeek
@load ./site/dns-anomalies.zeek
@load ./site/tls-anomalies.zeek
@load ./site/http-post-anomalies.zeek
