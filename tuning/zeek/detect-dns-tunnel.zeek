# ============================================================================
# detect-dns-tunnel.zeek — DNS tunneling and anomaly detection
# Phase 2 tuned configuration — ISE5901 Lab
#
# Detects unusually long DNS queries and high-volume DNS activity from
# single sources, which may indicate DNS-based C2 or data exfiltration.
#
# While Empire and Sliver HTTP/HTTPS profiles don't use DNS tunneling
# in this experiment, this script provides coverage for the DNS C2
# channel and demonstrates behavioral detection applicable to future
# framework profiles.
#
# Deploy to: /opt/zeek/share/zeek/site/detect-dns-tunnel.zeek
# Load via:  @load detect-dns-tunnel  in local.zeek
# ============================================================================

@load base/frameworks/notice
@load base/frameworks/sumstats

module DNSTunnel;

export {
    redef enum Notice::Type += {
        ## Raised when a DNS query exceeds the expected maximum length,
        ## which may indicate encoded data in DNS labels.
        Long_DNS_Query,

        ## Raised when a single source generates an abnormally high
        ## volume of DNS queries in a short time window.
        High_DNS_Query_Volume
    };

    ## Maximum query length before flagging as anomalous
    const max_query_length: count = 50 &redef;

    ## Minimum DNS queries from a single source before flagging volume
    const volume_threshold: count = 200 &redef;

    ## Time window for tracking DNS query volume
    const volume_window: interval = 10 min &redef;
}

# ── SumStats: Track DNS query volume per source ─────────────────────────

event zeek_init()
{
    local r1 = SumStats::Reducer(
        $stream="dns_tunnel.query_volume",
        $apply=set(SumStats::SUM)
    );

    SumStats::create([
        $name="detect-dns-volume",
        $epoch=volume_window,
        $reducers=set(r1),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
        {
            return result["dns_tunnel.query_volume"]$sum;
        },
        $threshold=volume_threshold * 1.0,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
        {
            NOTICE([
                $note=High_DNS_Query_Volume,
                $msg=fmt("Host %s generated %d DNS queries in %s",
                         key$host,
                         double_to_count(result["dns_tunnel.query_volume"]$sum),
                         volume_window),
                $src=key$host,
                $identifier=cat(key$host),
                $suppress_for=10 min
            ]);
        }
    ]);
}

# ── Event handlers ───────────────────────────────────────────────────────

event dns_request(c: connection, msg: dns_msg, query: string,
                  qtype: count, qclass: count)
{
    # Track volume per source
    SumStats::observe(
        "dns_tunnel.query_volume",
        SumStats::Key($host=c$id$orig_h),
        SumStats::Observation($num=1)
    );

    # Flag individual long queries immediately
    if ( |query| > max_query_length )
    {
        NOTICE([
            $note=Long_DNS_Query,
            $msg=fmt("Unusually long DNS query (%d chars) from %s: %s",
                     |query|, c$id$orig_h, query),
            $conn=c,
            $identifier=cat(c$id$orig_h, query),
            $suppress_for=5 min
        ]);
    }
}
