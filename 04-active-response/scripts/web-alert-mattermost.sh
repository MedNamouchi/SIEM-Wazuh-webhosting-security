#!/bin/bash
# =============================================================================
# Wazuh Active Response — web-alert-mattermost.sh
# Contextual Mattermost alerts for web hosting attacks
# Rules: 200100-200600
# Author: Mohamed Amine Namouchi — OFIR LTD internship 2026
# =============================================================================

LOG_FILE="/var/ossec/logs/active-responses.log"
MATTERMOST_WEBHOOK="<YOUR_MATTERMOST_WEBHOOK_URL>"
WAZUH_DASHBOARD="<YOUR_WAZUH_DASHBOARD_URL>"

INPUT=$(timeout 3 cat)
echo "$(date '+%Y-%m-%d %H:%M:%S') - [WEB-ALERT-MM] triggered" >> "$LOG_FILE"

# Validate JSON
if ! echo "$INPUT" | jq -e . > /dev/null 2>&1; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [WEB-ALERT-MM] ERROR: Invalid JSON" >> "$LOG_FILE"
    exit 1
fi

COMMAND=$(echo "$INPUT" | jq -r '.command // empty')
ALERT=$(echo "$INPUT" | jq -c '.parameters.alert // empty')

if [ "$COMMAND" != "add" ]; then exit 0; fi

# Extract fields
RULE_ID=$(echo "$ALERT"      | jq -r '.rule.id                // "unknown"')
RULE_DESC=$(echo "$ALERT"    | jq -r '.rule.description       // "unknown"')
LEVEL=$(echo "$ALERT"        | jq -r '.rule.level             // "0"')
SRCIP=$(echo "$ALERT"        | jq -r '.data.srcip             // "N/A"')
VHOST=$(echo "$ALERT"        | jq -r '.data.vhost             // "N/A"')
URL=$(echo "$ALERT"          | jq -r '.data.url               // "N/A"')
UA=$(echo "$ALERT"           | jq -r '.data.user_agent        // "N/A"')
TIMESTAMP=$(echo "$ALERT"    | jq -r '.timestamp              // "N/A"')
FIRED=$(echo "$ALERT"        | jq -r '.rule.firedtimes        // "1"')
MITRE_ID=$(echo "$ALERT"     | jq -r '.rule.mitre.id[0]       // "N/A"')
MITRE_TECH=$(echo "$ALERT"   | jq -r '.rule.mitre.technique[0] // "N/A"')
FULL_LOG=$(echo "$ALERT"     | jq -r '.full_log               // "N/A"' | head -c 300)
FILEPATH=$(echo "$ALERT"     | jq -r '.syscheck.path          // "N/A"')

# Geolocation enrichment
COUNTRY="Unknown"; CITY="Unknown"; ORG="Unknown"
if [ "$SRCIP" != "N/A" ] && [ "$SRCIP" != "null" ]; then
    GEO=$(curl -s --max-time 3 "https://ipapi.co/${SRCIP}/json/" 2>/dev/null)
    if echo "$GEO" | jq -e . > /dev/null 2>&1; then
        COUNTRY=$(echo "$GEO" | jq -r '.country_name // "Unknown"')
        CITY=$(echo "$GEO"    | jq -r '.city         // "Unknown"')
        ORG=$(echo "$GEO"     | jq -r '.org          // "Unknown"')
    fi
fi

# Contextual emoji and title per rule ID
case "$RULE_ID" in
    200100) ICON="🔑";    TITLE="WordPress Login Attempt" ;;
    200101) ICON="🔑🔑";  TITLE="WordPress Brute Force" ;;
    200102) ICON="👤";    TITLE="WordPress User Enumeration" ;;
    200103) ICON="👤⚡";  TITLE="Rapid User Enumeration" ;;
    200105) ICON="🔌";    TITLE="XML-RPC Abuse" ;;
    200106) ICON="💀";    TITLE="Plugin Upload / Webshell Drop" ;;
    200200) ICON="🤖";    TITLE="Scanner Detected" ;;
    200201) ICON="🔍";    TITLE="Internet Indexer" ;;
    200202) ICON="🌊";    TITLE="404 Flood" ;;
    200203) ICON="🌊🌊";  TITLE="High Request Rate" ;;
    200300) ICON="💉";    TITLE="SQL Injection Attempt" ;;
    200301) ICON="⚡";    TITLE="XSS Attempt" ;;
    200302) ICON="📂";    TITLE="Path Traversal Attempt" ;;
    200303) ICON="🔓";    TITLE="Sensitive File Access" ;;
    200304) ICON="🔥";    TITLE="Remote File Inclusion" ;;
    200305) ICON="💣";    TITLE="Command Injection" ;;
    200306) ICON="💀🔥";  TITLE="WEBSHELL ACCESS DETECTED" ;;
    200400) ICON="🚨";    TITLE="New PHP File Created — Possible Webshell" ;;
    200401) ICON="⚠️";   TITLE="PHP File Modified" ;;
    200402) ICON="⚙️";   TITLE="Config File Modified" ;;
    200501) ICON="🔐";    TITLE="Webmin Auth Failure" ;;
    200502) ICON="🔐🔐";  TITLE="Webmin Brute Force" ;;
    200600) ICON="⚫";    TITLE="MySQL Node Direct Access" ;;
    *)      ICON="ℹ️";   TITLE="Security Alert" ;;
esac

# Build Mattermost message
MM_TEXT="${ICON} **${TITLE}**
**Rule:** ${RULE_ID} | **Level:** ${LEVEL}/15 | **Fired:** ${FIRED}x
**IP:** \`${SRCIP}\` — 📍 ${CITY}, ${COUNTRY} (${ORG})
**Site:** ${VHOST} | **URL:** ${URL}
**User-Agent:** ${UA}
**MITRE:** ${MITRE_ID} — ${MITRE_TECH}
**Time:** ${TIMESTAMP}
**Log:** \`${FULL_LOG}\`"

# Add filepath for FIM alerts
if [ "$FILEPATH" != "N/A" ]; then
    MM_TEXT="${MM_TEXT}
**File:** \`${FILEPATH}\`"
fi

MM_TEXT="${MM_TEXT}
🔗 [Dashboard](${WAZUH_DASHBOARD})"

MM_PAYLOAD=$(jq -n --arg text "$MM_TEXT" '{text: $text}')

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "$MM_PAYLOAD" "$MATTERMOST_WEBHOOK")

if [ "$HTTP_CODE" = "200" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [WEB-ALERT-MM] SENT — Rule: $RULE_ID — IP: $SRCIP — Site: $VHOST" >> "$LOG_FILE"
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [WEB-ALERT-MM] ERROR: HTTP $HTTP_CODE" >> "$LOG_FILE"
fi

exit 0
