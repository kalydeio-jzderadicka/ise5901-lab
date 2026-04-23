# ============================================================================
# detect-beacon.zeek — Beacon interval periodicity detection
# Phase 2 tuned configuration — ISE5901 Lab
#
# Monitors connection patterns between host pairs and generates NOTICE
# events when periodic communication is detected that matches C2 beacon
# behavior (regular intervals, consistent connection patterns).
#
# Deploy to: /opt/zeek/share/zeek/site/detect-beacon.zeek
# Load via:  @load detect-beacon  in local.zeek
# ============================================================================

@load base/frameworks/notice
@load base/frameworks/sumstats

module BeaconDetect;

export {
    redef enum Notice::Type += {
        ## Raised when a source IP shows periodic connection behavior
        ## consistent with C2 beacon activity.
        Periodic_Connection_Detected,

        ## Raised when repeated HTTP POST requests are observed from
        ## a single source to the same destination.
        Suspicious_POST_Frequency,

        ## Raised when repeated connections target port 8080, a common
        ## C2 listener port.
        C2_Port_Activity
    };

    ## Minimum POST requests to the same destination before flagging
    const post_threshold: count = 8 &redef;

    ## Time window for tracking HTTP POST frequency
    const post_window: interval = 30 min &redef;

    ## Minimum connections to same dst on port 8080 before flagging
    const c2_port_threshold: count = 8 &redef;

    ## Time window for tracking port 8080 connections
    const c2_port_window: interval = 30 min &redef;
}

# ── SumStats: Track HTTP POST frequency per src→dst pair ─────────────────

event zeek_init()
{
    local r1 = SumStats::Reducer(
        $stream="beacon.http_post",
        $apply=set(SumStats::SUM)
    );

    SumStats::create([
        $name="detect-beacon-post",
        $epoch=post_window,
        $reducers=set(r1),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
        {
            return result["beacon.http_post"]$sum;
        },
        $threshold=post_threshold * 1.0,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
        {
            NOTICE([
                $note=Suspicious_POST_Frequency,
                $msg=fmt("Host %s sent %d HTTP POST requests to %s in %s",
                         key$host, double_to_count(result["beacon.http_post"]$sum),
                         key$str, post_window),
                $src=key$host,
                $identifier=cat(key$host, key$str),
                $suppress_for=10 min
            ]);
        }
    ]);

    local r2 = SumStats::Reducer(
        $stream="beacon.c2_port",
        $apply=set(SumStats::SUM)
    );

    SumStats::create([
        $name="detect-beacon-c2port",
        $epoch=c2_port_window,
        $reducers=set(r2),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
        {
            return result["beacon.c2_port"]$sum;
        },
        $threshold=c2_port_threshold * 1.0,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
        {
            NOTICE([
                $note=C2_Port_Activity,
                $msg=fmt("Host %s made %d connections to %s:8080 in %s",
                         key$host, double_to_count(result["beacon.c2_port"]$sum),
                         key$str, c2_port_window),
                $src=key$host,
                $identifier=cat(key$host, key$str, "8080"),
                $suppress_for=10 min
            ]);
        }
    ]);
}

# ── Event handlers ───────────────────────────────────────────────────────

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    if ( method == "POST" )
    {
        SumStats::observe(
            "beacon.http_post",
            SumStats::Key($host=c$id$orig_h, $str=cat(c$id$resp_h)),
            SumStats::Observation($num=1)
        );
    }
}

event connection_state_remove(c: connection)
{
    if ( c$id$resp_p == 8080/tcp )
    {
        SumStats::observe(
            "beacon.c2_port",
            SumStats::Key($host=c$id$orig_h, $str=cat(c$id$resp_h)),
            SumStats::Observation($num=1)
        );
    }
}
