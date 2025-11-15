#!/bin/bash

# Cron gibi kısıtlı ortamlarda çalışabilmesi için komutların tam yolları belirtildi.
IPTABLES_CMD="/usr/sbin/iptables"
IPSET_CMD="/usr/sbin/ipset"

# iptables nat tablosu temizliği
$IPTABLES_CMD -t nat -D PREROUTING -j DDOS_GATEWAY &> /dev/null
$IPTABLES_CMD -t nat -F DDOS_GATEWAY &> /dev/null
$IPTABLES_CMD -t nat -X DDOS_GATEWAY &> /dev/null

# iptables filter tablosu temizliği
$IPTABLES_CMD -D INPUT -j DDOS_FILTER &> /dev/null
$IPTABLES_CMD -F DDOS_FILTER &> /dev/null
$IPTABLES_CMD -X DDOS_FILTER &> /dev/null

# ipset listesi temizliği
$IPSET_CMD destroy ddos_blocklist &> /dev/null
$IPSET_CMD destroy ddos_whitelist &> /dev/null 
