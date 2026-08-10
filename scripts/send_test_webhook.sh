#!/usr/bin/env bash

# Default variables
HOST="127.0.0.1"
PORT="8000"
TOKEN="test"

echo "=== ESET SOC Lite - Webhook Test Script ==="
echo "Targeting http://$HOST:$PORT/webhook/eset"
echo ""

# Helper to generate randomized alert ID
generate_alert_id() {
    echo "test-alert-$(date +%s)-$((RANDOM % 10000))"
}

# Payload definition templates
LOW_PAYLOAD() {
    cat <<EOF
{
  "source": "ESET_PROTECT_CLOUD",
  "event_type": "Threat Detection",
  "alert_id": "$(generate_alert_id)",
  "detection_uuid": "e9b724fa-774f-4d69-a1b9-1234567890ab",
  "target_uuid": "c3d5f6a7-8e9f-0a1b-2c3d-4e5f6a7b8c9d",
  "occurred_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "severity": "LOW",
  "detection_name": "JS/Adware.Agent.AA",
  "endpoint_name": "DESKTOP-CLIENT-01",
  "endpoint_type": "Workstation",
  "user_name": "john.doe",
  "os_name": "Windows 11",
  "action_taken": "Cleaned by deleting",
  "threat_handled": true,
  "isolation_status": false,
  "object_type": "File",
  "object_uri": "C:\\\\Users\\\\john.doe\\\\Downloads\\\\adware_installer.js",
  "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "url": "http://example-adware-domain.com/installer.js",
  "ip_address": "192.168.1.105",
  "domain": "example-adware-domain.com",
  "raw_subject": "Low Adware detection on DESKTOP-CLIENT-01",
  "raw_content": "A threat (JS/Adware.Agent.AA) was detected on computer DESKTOP-CLIENT-01. The threat was successfully cleaned."
}
EOF
}

MEDIUM_PAYLOAD() {
    cat <<EOF
{
  "source": "ESET_PROTECT_CLOUD",
  "event_type": "Threat Detection",
  "alert_id": "$(generate_alert_id)",
  "detection_uuid": "f2a345bc-cd4e-56fg-78hi-1234567890cd",
  "target_uuid": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "occurred_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "severity": "MEDIUM",
  "detection_name": "Win32/Spy.Agent.ODS",
  "endpoint_name": "DESKTOP-CLIENT-02",
  "endpoint_type": "Workstation",
  "user_name": "alice.smith",
  "os_name": "Windows 11",
  "action_taken": "Blocked",
  "threat_handled": false,
  "isolation_status": false,
  "object_type": "File",
  "object_uri": "C:\\\\Users\\\\alice.smith\\\\AppData\\\\Local\\\\Temp\\\\spy_tool.exe",
  "file_hash": "2f0e3456bc987654a1d2e3f4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4",
  "url": "http://spyware-distribution-hub.ru/spy_tool.exe",
  "ip_address": "81.95.20.142",
  "domain": "spyware-distribution-hub.ru",
  "raw_subject": "Suspicious application blocked on DESKTOP-CLIENT-02",
  "raw_content": "A suspicious threat (Win32/Spy.Agent.ODS) was blocked on DESKTOP-CLIENT-02. The file remains uncleaned on the system."
}
EOF
}

HIGH_PAYLOAD() {
    cat <<EOF
{
  "source": "ESET_PROTECT_CLOUD",
  "event_type": "Threat Detection",
  "alert_id": "$(generate_alert_id)",
  "detection_uuid": "f4b5c6d7-e8f9-0a1b-2c3d-4e5f6a7b8c9d",
  "target_uuid": "z1x2c3v4-b5n6-m7q8-w9e0-r1t2y3u4i5o6",
  "occurred_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "severity": "HIGH",
  "detection_name": "Win32/TrojanDownloader.Agent.YHV",
  "endpoint_name": "FINANCE-PC-09",
  "endpoint_type": "Server",
  "user_name": "charlie.brown",
  "os_name": "Windows Server 2022",
  "action_taken": "Connection terminated",
  "threat_handled": false,
  "isolation_status": false,
  "object_type": "Process",
  "object_uri": "C:\\\\Windows\\\\System32\\\\cmd.exe",
  "file_hash": "a4f5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5",
  "url": "http://malicious-command-control-node.com/shell",
  "ip_address": "185.220.101.5",
  "domain": "malicious-command-control-node.com",
  "raw_subject": "High Risk Trojan Activity on Server FINANCE-PC-09",
  "raw_content": "A connection from cmd.exe to a known command-and-control server (185.220.101.5) was detected and blocked. Shell active in memory."
}
EOF
}

CRITICAL_PAYLOAD() {
    cat <<EOF
{
  "source": "ESET_PROTECT_CLOUD",
  "event_type": "Threat Detection",
  "alert_id": "$(generate_alert_id)",
  "detection_uuid": "f9e8d7c6-b5a4-3210-fe0d-1234567890fe",
  "target_uuid": "h1j2k3l4-m5n6-o7p8-q9r0-s1t2u3v4w5x6",
  "occurred_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "severity": "CRITICAL",
  "detection_name": "Win32/Filecoder.WannaCryptor.D",
  "endpoint_name": "DOMAIN-CONTROLLER-01",
  "endpoint_type": "Domain Controller",
  "user_name": "administrator",
  "os_name": "Windows Server 2019",
  "action_taken": "Failed to clean",
  "threat_handled": false,
  "isolation_status": false,
  "object_type": "File",
  "object_uri": "C:\\\\Windows\\\\temp\\\\tasksche.exe",
  "file_hash": "24f5e0a6123456789abcdef0123456789abcdef0123456789abcdef012345678",
  "url": "http://wanna-c2-hidden-service.onion/keys",
  "ip_address": "109.201.133.100",
  "domain": "wanna-c2-hidden-service.onion",
  "raw_subject": "CRITICAL RANSOMWARE DETECTION ON DOMAIN-CONTROLLER-01",
  "raw_content": "WannaCryptor.D file coder activity was detected on DOMAIN-CONTROLLER-01. Mitigation attempt failed. Files are actively being encrypted."
}
EOF
}

send_request() {
    local risk=$1
    local json_payload
    
    case $risk in
        "low") json_payload=$(LOW_PAYLOAD) ;;
        "medium") json_payload=$(MEDIUM_PAYLOAD) ;;
        "high") json_payload=$(HIGH_PAYLOAD) ;;
        "critical") json_payload=$(CRITICAL_PAYLOAD) ;;
        *) echo "Unknown risk category $risk"; exit 1 ;;
    esac
    
    echo "Sending $risk risk payload..."
    curl -i -X POST "http://$HOST:$PORT/webhook/eset" \
         -H "Authorization: Bearer $TOKEN" \
         -H "Content-Type: application/json" \
         -d "$json_payload"
         
    echo -e "\n\n"
}

# If arguments provided, run specific payloads
if [ $# -gt 0 ]; then
    send_request "$1"
else
    # Run all
    send_request "low"
    send_request "medium"
    send_request "high"
    send_request "critical"
fi
