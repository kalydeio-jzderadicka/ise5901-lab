# ============================================================================
# detect-user-agent.zeek — HTTP user-agent anomaly detection
# Phase 2 tuned configuration — ISE5901 Lab
#
# Flags known-suspicious user-agent strings observed in C2 frameworks:
#   - PowerShell user-agents (Empire default)
#   - Outdated browser versions (Sliver uses Chrome 106)
#   - curl/wget from internal hosts (stager delivery patterns)
#
# Deploy to: /opt/zeek/share/zeek/site/detect-user-agent.zeek
# Load via:  @load detect-user-agent  in local.zeek
# ============================================================================

@load base/frameworks/notice

module UserAgentDetect;

export {
    redef enum Notice::Type += {
        ## PowerShell or scripting-engine user-agent in HTTP traffic
        Scripting_UserAgent,

        ## Outdated or known-C2 browser user-agent string
        Suspicious_UserAgent,

        ## curl/wget from internal host (potential stager delivery)
        CLI_Tool_UserAgent
    };

    ## Set of user-agent substrings that indicate scripting engines
    const scripting_ua_patterns: set[string] = {
        "WindowsPowerShell",
        "PowerShell",
        "python-requests",
        "Python-urllib"
    } &redef;

    ## Set of outdated/known-bad browser version strings
    const suspicious_ua_patterns: set[string] = {
        "Chrome/106.0",
        "Chrome/105.0",
        "Chrome/104.0"
    } &redef;

    ## Set of CLI tool user-agent indicators
    const cli_ua_patterns: set[string] = {
        "curl/",
        "Wget/",
        "libwww-perl"
    } &redef;
}

event http_header(c: connection, is_orig: bool, original_name: string,
                  name: string, value: string)
{
    if ( ! is_orig || name != "USER-AGENT" )
        return;

    for ( pat in scripting_ua_patterns )
    {
        if ( pat in value )
        {
            NOTICE([
                $note=Scripting_UserAgent,
                $msg=fmt("Scripting user-agent detected from %s to %s:%s — %s",
                         c$id$orig_h, c$id$resp_h, c$id$resp_p, value),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h, pat),
                $suppress_for=10 min
            ]);
            return;
        }
    }

    for ( pat in suspicious_ua_patterns )
    {
        if ( pat in value )
        {
            NOTICE([
                $note=Suspicious_UserAgent,
                $msg=fmt("Suspicious user-agent from %s to %s:%s — %s",
                         c$id$orig_h, c$id$resp_h, c$id$resp_p, value),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h, pat),
                $suppress_for=10 min
            ]);
            return;
        }
    }

    for ( pat in cli_ua_patterns )
    {
        if ( pat in value )
        {
            NOTICE([
                $note=CLI_Tool_UserAgent,
                $msg=fmt("CLI tool user-agent from %s to %s:%s — %s",
                         c$id$orig_h, c$id$resp_h, c$id$resp_p, value),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h, pat),
                $suppress_for=10 min
            ]);
            return;
        }
    }
}
