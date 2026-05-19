# Day 3 — Firewalls & Router Integration

> **Goal:** Network devices forwarding syslog to Wazuh. Logs correctly received, parsed, decoded, and generating security alerts.  
> **Estimated time:** 6–8 hours

---

## Why Day 3 Is Dedicated to This

Network devices (firewalls, routers, switches) **cannot install the Wazuh agent**. They must forward logs via **Syslog (UDP/514 or TCP/514)** to the Wazuh Manager, which acts as a syslog collector. This is conceptually simple but practically challenging because:

1. Each vendor has a different log format
2. You need custom decoders if Wazuh doesn't natively support the device
3. Syslog is UDP by default — logs can be lost silently
4. Timezone mismatches between devices and the SIEM corrupt correlation

**Plan for this day to be mostly troubleshooting.** Getting the first log parsed correctly is 80% of the work.

---

## 3.1 Verify Syslog Listener (Already Configured on Day 1)

The syslog listener was already added to `ossec.conf` on Day 1:

```xml
<remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>192.168.10.0/24</allowed-ips>
</remote>
```

> [!WARNING]
> If you need TCP syslog (more reliable, no lost packets), add a **second** `<remote>` block:
> ```xml
> <remote>
>     <connection>syslog</connection>
>     <port>514</port>
>     <protocol>tcp</protocol>
>     <allowed-ips>192.168.10.0/24</allowed-ips>
> </remote>
> ```
> Restart the manager after adding.

### Verify the Listener Is Active

```bash
# Check that port 514 is listening
ss -ulnp | grep 514
# Expected: udp  UNCONN  0  0  0.0.0.0:514  0.0.0.0:*  users:(("wazuh-remoted",...))

# If using TCP as well:
ss -tlnp | grep 514
```

---

## 3.2 Configure Network Devices to Forward Syslog

### Fortinet FortiGate

```
# FortiGate CLI
config log syslogd setting
    set status enable
    set server "YOUR_WAZUH_MANAGER_IP"
    set port 514
    set facility local7
    set format default
end

# Enable traffic, event, and UTM logging
config log syslogd filter
    set severity information
    set forward-traffic enable
    set local-traffic enable
    set multicast-traffic enable
    set anomaly enable
    set dns enable
    set ssh enable
    set filter ""
end
```

### pfSense / OPNsense

1. **System → Settings → Logging → Remote**
2. Enable **Send log messages to remote syslog server**
3. Remote log server: `YOUR_WAZUH_MANAGER_IP:514`
4. Remote Syslog Contents: Check **Everything** or at minimum:
   - Firewall Events
   - System Events  
   - DNS Events
   - OpenVPN Events
5. Click **Save**

### Palo Alto Networks

```
# Palo Alto CLI
set shared log-settings syslog WazuhSIEM server WazuhServer server YOUR_WAZUH_MANAGER_IP
set shared log-settings syslog WazuhSIEM server WazuhServer transport UDP
set shared log-settings syslog WazuhSIEM server WazuhServer port 514
set shared log-settings syslog WazuhSIEM server WazuhServer format BSD
set shared log-settings syslog WazuhSIEM server WazuhServer facility LOG_LOCAL7

# Create syslog forwarding profile and assign to security rules
```

### MikroTik RouterOS

```
# MikroTik CLI
/system logging action
add name=wazuh-syslog target=remote remote=YOUR_WAZUH_MANAGER_IP remote-port=514 \
    bsd-syslog=yes syslog-facility=local7

/system logging
add action=wazuh-syslog topics=firewall
add action=wazuh-syslog topics=system
add action=wazuh-syslog topics=warning
add action=wazuh-syslog topics=error
add action=wazuh-syslog topics=critical
add action=wazuh-syslog topics=info
```

---

## 3.3 Verify Logs Are Arriving (Critical Step)

```bash
# Quick test: watch raw syslog arriving on the manager
# This is the FIRST thing to check — if nothing shows up here, it's a network problem
tcpdump -i any -n port 514 -c 20

# Then check Wazuh's archive logs (raw, undecoded)
# Enable temporary full logging to see ALL incoming data:
# In ossec.conf, set:
#   <logall>yes</logall>
#   <logall_json>yes</logall_json>
# Then restart, check:
tail -f /var/ossec/logs/archives/archives.log | grep -i "firewall\|fortigate\|pfsense\|mikrotik"
```

> **⚠️ PITFALL — "I see no syslog data":**  
> 1. **Firewall blocking:** Is `514/UDP` open between the device and the manager? Test: `nc -u YOUR_WAZUH_IP 514 <<< "test syslog message"`
> 2. **Wrong `allowed-ips`:** The `<remote>` block's `<allowed-ips>` must match the source IP of the network device
> 3. **Device not sending:** Generate traffic on the firewall (e.g., block a connection) and check if syslog increases
> 4. **DNS resolution:** Some devices try to resolve the syslog server hostname. Use IP addresses instead.

---

## 3.4 Custom Decoders for Network Devices

Wazuh has built-in decoders for FortiGate and some other vendors. However, for **OPNsense**, **pfSense**, and **MikroTik**, you likely need custom decoders.

### Check if Built-in Decoders Work First

```bash
# Use wazuh-logtest to test a raw syslog line
/var/ossec/bin/wazuh-logtest

# Paste a real log line from your device. If it says "No decoder matched", you need a custom one.
# If it decodes to a generic syslog decoder, you need a more specific one.
```

### FortiGate Decoder (Usually Built-in)

FortiGate logs are typically decoded by Wazuh's built-in `fortigate` decoder. Verify:

```bash
/var/ossec/bin/wazuh-logtest
# Paste: date=2026-05-19 time=10:30:00 devname="FW01" devid="FG100E" logid="0001000014" type="traffic" subtype="forward" level="notice" srcip=192.168.1.100 dstip=8.8.8.8 action="accept"
```

If decoded correctly, FortiGate is ready out of the box.

### OPNsense Custom Decoder

Create `/var/ossec/etc/decoders/opnsense_decoder.xml`:

```xml
<!-- OPNsense Firewall Decoder -->
<decoder name="opnsense-filterlog">
    <prematch>filterlog\[\d+\]:</prematch>
</decoder>

<decoder name="opnsense-filterlog-fields">
    <parent>opnsense-filterlog</parent>
    <regex type="pcre2">filterlog\[\d+\]:\s+(\d+),,,(\S+),(\S+),(\w+),(\w+),(\d+),\S+,\S+,\d+,\d+,\d+,\S+,(\d+),(\w+),(\d+),(\d+),\d+,(\w+),(\S+),(\S+),(\d+),(\d+)</regex>
    <order>rule_number,interface_name,interface_description,action,direction,ip_version,protocol_id,protocol_name,src_length,dst_length,extra_field,srcip,dstip,srcport,dstport</order>
</decoder>

<!-- Suricata IDS via OPNsense -->
<decoder name="opnsense-suricata">
    <prematch>suricata\[\d+\]:</prematch>
</decoder>

<decoder name="opnsense-suricata-fields">
    <parent>opnsense-suricata</parent>
    <regex type="pcre2">\[(\d+):(\d+):(\d+)\]\s+(.+?)\s+\[Classification:\s+(.+?)\]\s+\[Priority:\s+(\d+)\].*?(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+):(\d+)</regex>
    <order>gid,sid,rev,signature,classification,priority,srcip,srcport,dstip,dstport</order>
</decoder>

<!-- OPNsense System / General -->
<decoder name="opnsense-system">
    <prematch type="pcre2">^[\w\s]+\d+ \d+:\d+:\d+ \S+ (\w+)\[</prematch>
</decoder>
```

### MikroTik Custom Decoder

Create `/var/ossec/etc/decoders/mikrotik_decoder.xml`:

```xml
<!-- MikroTik RouterOS Decoder -->
<decoder name="mikrotik-general">
    <prematch type="pcre2">\b(system|firewall|wireless|dhcp|dns|interface|ipsec|l2tp|pptp|ovpn|hotspot|certificate|account)\b,</prematch>
</decoder>

<!-- MikroTik Firewall Log -->
<decoder name="mikrotik-firewall">
    <parent>mikrotik-general</parent>
    <prematch>firewall,</prematch>
    <regex type="pcre2">firewall,\w+\s+(\S+)\s+in:(\S+)\s+out:(\S*),?\s*(?:connection-state:(\S+))?,?\s*src-mac\s+([\da-f:]+),?\s*proto\s+(\w+),?\s*(\d+\.\d+\.\d+\.\d+):?(\d*)->(\d+\.\d+\.\d+\.\d+):?(\d*)</regex>
    <order>action,in_interface,out_interface,connection_state,src_mac,protocol,srcip,srcport,dstip,dstport</order>
</decoder>

<!-- MikroTik Login Events -->
<decoder name="mikrotik-login">
    <parent>mikrotik-general</parent>
    <prematch>system,</prematch>
    <regex type="pcre2">user\s+(\S+)\s+logged\s+in\s+from\s+(\d+\.\d+\.\d+\.\d+)</regex>
    <order>user,srcip</order>
</decoder>

<!-- MikroTik DHCP -->
<decoder name="mikrotik-dhcp">
    <parent>mikrotik-general</parent>
    <prematch>dhcp,</prematch>
    <regex type="pcre2">(\S+)\s+(\w+)\s+(\d+\.\d+\.\d+\.\d+)\s+for\s+([\da-fA-F:]+)</regex>
    <order>pool_name,action,srcip,src_mac</order>
</decoder>
```

---

## 3.5 Custom Rules for Network Devices

Create `/var/ossec/etc/rules/network_devices_rules.xml`:

```xml
<group name="network_devices,firewall,">

    <!-- ═══════════════════════════════════════════ -->
    <!--  FORTINET FORTIGATE                         -->
    <!-- ═══════════════════════════════════════════ -->

    <!-- FortiGate: High-severity UTM event -->
    <rule id="100100" level="12">
        <if_sid>81600</if_sid>
        <field name="fortigate.level">alert|critical|emergency</field>
        <description>FortiGate CRITICAL: $(fortigate.type) — $(fortigate.msg)</description>
        <group>fortigate,attack,</group>
    </rule>

    <!-- FortiGate: IPS Detection -->
    <rule id="100101" level="10">
        <if_sid>81600</if_sid>
        <field name="fortigate.type">utm</field>
        <field name="fortigate.subtype">ips</field>
        <description>FortiGate IPS: Attack detected — $(fortigate.attack)</description>
        <mitre>
            <id>T1190</id>
        </mitre>
        <group>fortigate,ids,</group>
    </rule>

    <!-- FortiGate: VPN login failure -->
    <rule id="100102" level="8">
        <if_sid>81600</if_sid>
        <field name="fortigate.type">event</field>
        <match>ssl-login-fail|tunnel-down</match>
        <description>FortiGate: VPN authentication failure from $(srcip).</description>
        <mitre>
            <id>T1133</id>
        </mitre>
        <group>fortigate,authentication_failure,</group>
    </rule>

    <!-- FortiGate: Admin login -->
    <rule id="100103" level="6">
        <if_sid>81600</if_sid>
        <field name="fortigate.type">event</field>
        <field name="fortigate.subtype">system</field>
        <match>Admin login successful</match>
        <description>FortiGate: Admin login from $(srcip).</description>
        <group>fortigate,authentication_success,</group>
    </rule>

    <!-- ═══════════════════════════════════════════ -->
    <!--  OPNSENSE / PFSENSE                         -->
    <!-- ═══════════════════════════════════════════ -->

    <!-- OPNsense: Blocked connection (firewall rule) -->
    <rule id="100110" level="4">
        <decoded_as>opnsense-filterlog-fields</decoded_as>
        <field name="action">block</field>
        <description>OPNsense: Blocked $(protocol_name) connection $(srcip):$(srcport) → $(dstip):$(dstport)</description>
        <group>opnsense,firewall_block,</group>
    </rule>

    <!-- OPNsense: Port scan detection (>10 blocked in 2 min from same source) -->
    <rule id="100111" level="10" frequency="10" timeframe="120">
        <if_matched_sid>100110</if_matched_sid>
        <same_srcip />
        <description>OPNsense: Possible port scan from $(srcip) — multiple blocked connections.</description>
        <mitre>
            <id>T1046</id>
        </mitre>
        <group>opnsense,port_scan,attack,</group>
    </rule>

    <!-- OPNsense: Suricata IDS Alert -->
    <rule id="100112" level="10">
        <decoded_as>opnsense-suricata-fields</decoded_as>
        <description>OPNsense Suricata IDS: $(signature) [Priority: $(priority)] — $(srcip) → $(dstip)</description>
        <mitre>
            <id>T1190</id>
        </mitre>
        <group>opnsense,ids,</group>
    </rule>

    <!-- OPNsense: Suricata Critical (Priority 1) -->
    <rule id="100113" level="14">
        <if_sid>100112</if_sid>
        <field name="priority">1</field>
        <description>CRITICAL: OPNsense Suricata HIGH-PRIORITY alert — $(signature)</description>
        <group>opnsense,ids,critical,</group>
    </rule>

    <!-- ═══════════════════════════════════════════ -->
    <!--  MIKROTIK ROUTEROS                           -->
    <!-- ═══════════════════════════════════════════ -->

    <!-- MikroTik: Firewall drop -->
    <rule id="100120" level="4">
        <decoded_as>mikrotik-firewall</decoded_as>
        <match>drop</match>
        <description>MikroTik: Dropped $(protocol) $(srcip):$(srcport) → $(dstip):$(dstport) on $(in_interface)</description>
        <group>mikrotik,firewall_block,</group>
    </rule>

    <!-- MikroTik: Port scan detection -->
    <rule id="100121" level="10" frequency="15" timeframe="120">
        <if_matched_sid>100120</if_matched_sid>
        <same_srcip />
        <description>MikroTik: Possible port scan from $(srcip) — multiple drops.</description>
        <mitre>
            <id>T1046</id>
        </mitre>
        <group>mikrotik,port_scan,attack,</group>
    </rule>

    <!-- MikroTik: Admin login success -->
    <rule id="100122" level="6">
        <decoded_as>mikrotik-login</decoded_as>
        <description>MikroTik: Admin user $(user) logged in from $(srcip).</description>
        <group>mikrotik,authentication_success,</group>
    </rule>

    <!-- MikroTik: Admin login from external IP -->
    <rule id="100123" level="12">
        <if_sid>100122</if_sid>
        <not_srcip>192.168.0.0/16,10.0.0.0/8,172.16.0.0/12</not_srcip>
        <description>CRITICAL: MikroTik admin login from EXTERNAL IP $(srcip)!</description>
        <mitre>
            <id>T1078</id>
        </mitre>
        <group>mikrotik,external_access,critical,</group>
    </rule>

    <!-- MikroTik: Failed login brute force -->
    <rule id="100124" level="12" frequency="5" timeframe="300">
        <if_sid>100122</if_sid>
        <same_srcip />
        <description>MikroTik: Brute force detected — multiple login attempts from $(srcip).</description>
        <mitre>
            <id>T1110</id>
        </mitre>
        <group>mikrotik,brute_force,attack,</group>
    </rule>

    <!-- ═══════════════════════════════════════════ -->
    <!--  PALO ALTO NETWORKS                          -->
    <!-- ═══════════════════════════════════════════ -->

    <!-- Palo Alto: Threat log -->
    <rule id="100130" level="10">
        <if_sid>64000</if_sid>
        <field name="pan.type">THREAT</field>
        <description>Palo Alto Threat: $(pan.threat_name) — $(srcip) → $(dstip)</description>
        <mitre>
            <id>T1190</id>
        </mitre>
        <group>paloalto,threat,</group>
    </rule>

    <!-- Palo Alto: Critical threat severity -->
    <rule id="100131" level="14">
        <if_sid>100130</if_sid>
        <field name="pan.severity">critical|high</field>
        <description>CRITICAL: Palo Alto HIGH-severity threat — $(pan.threat_name)</description>
        <group>paloalto,threat,critical,</group>
    </rule>

    <!-- Palo Alto: Admin login -->
    <rule id="100132" level="6">
        <if_sid>64000</if_sid>
        <field name="pan.type">SYSTEM</field>
        <match>auth-success|Login succeeded</match>
        <description>Palo Alto: Admin authentication from $(srcip).</description>
        <group>paloalto,authentication_success,</group>
    </rule>

</group>
```

---

## 3.6 Test Decoders with `wazuh-logtest`

This is **the most important step** of Day 3. Do not proceed until your decoders work.

```bash
/var/ossec/bin/wazuh-logtest
```

Paste real log lines from your devices. For each device type, you should see:

1. **Phase 1:** Decoder identified (not "No decoder matched")
2. **Phase 2:** Fields extracted correctly (srcip, dstip, action, etc.)
3. **Phase 3:** Rule matched (your custom rule IDs from 100100+)

### Example Test — FortiGate

```
Type one log per line:

date=2026-05-19 time=10:30:00 devname="FW01" devid="FG100E" logid="0001000014" type="traffic" subtype="forward" level="notice" srcip=10.10.10.50 dstip=185.220.101.1 action="accept"
```

### Example Test — MikroTik

```
Type one log per line:

May 19 10:30:00 MK01 firewall,info drop in:ether1 out:, src-mac 00:11:22:33:44:55, proto TCP, 185.220.101.1:45678->192.168.10.1:22
```

> **⚠️ PITFALL — Decoder not matching:**  
> The most common issue is that the actual log format from your specific device firmware version doesn't match the regex in the decoder. **Always test with REAL logs**, not documentation examples. Copy a line directly from `tcpdump` output or `/var/ossec/logs/archives/archives.log`.

---

## 3.7 Assign Syslog Sources to Agent Group

Syslog sources appear in Wazuh as events from agent `000` (the manager itself) by default. To logically separate them, use the `<location>` tag in your custom rules:

```xml
<!-- Example: Only fire this rule for syslog from the FortiGate IP -->
<rule id="100105" level="12">
    <if_sid>81600</if_sid>
    <srcip>192.168.10.1</srcip>   <!-- Your FortiGate IP -->
    <field name="fortigate.type">utm</field>
    <description>FortiGate UTM alert from production firewall.</description>
    <group>fortigate,network_devices,</group>
</rule>
```

> [!TIP]
> For better organization, you can configure your firewall to send syslog with a specific `hostname` field, and then use `<hostname>` in your rules to differentiate multiple devices of the same vendor.

---

## 3.8 Apply and Restart

```bash
# Validate XML syntax before restarting
xmllint --noout /var/ossec/etc/decoders/opnsense_decoder.xml
xmllint --noout /var/ossec/etc/decoders/mikrotik_decoder.xml
xmllint --noout /var/ossec/etc/rules/network_devices_rules.xml

# Restart manager
systemctl restart wazuh-manager

# Watch for errors
tail -30 /var/ossec/logs/ossec.log | grep -i "error\|warn"

# Verify alerts are flowing
tail -f /var/ossec/logs/alerts/alerts.json | jq 'select(.rule.groups[]? | contains("fortigate","opnsense","mikrotik"))' 2>/dev/null
```

---

## 3.9 Enable `logall` Temporarily for Debugging (Optional)

If you're struggling to see what's coming in, temporarily enable full logging:

```xml
<!-- In ossec.conf — TEMPORARY, disable after debugging -->
<global>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
</global>
```

```bash
systemctl restart wazuh-manager

# Watch everything — decoded and undecoded
tail -f /var/ossec/logs/archives/archives.json | jq '.full_log' | head -50
```

> [!CAUTION]
> **Disable `logall` when done debugging!** It writes EVERY event to disk, including low-level noise. On a busy network, this can consume gigabytes per day and fill your disk.

---

## Day 3 Checklist

```
✅ Syslog listener active on port 514 (UDP and/or TCP)
✅ Network device(s) configured to forward syslog to manager
✅ Raw syslog traffic confirmed arriving (tcpdump)
✅ Custom decoders installed for each device type
✅ wazuh-logtest validates correct decoding of real log lines
✅ Custom rules installed for firewall/router alerts
✅ Alerts from network devices visible in Dashboard → Security Events
✅ logall disabled (if it was temporarily enabled for debugging)
✅ No errors in /var/ossec/logs/ossec.log
```

---

**→ Proceed to [Day 4: MISP Threat Intelligence](./DAY4_MISP_Threat_Intelligence.md)**
