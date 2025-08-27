#!/usr/bin/env python3
"""
Simple Network Guardian - Basic Network Security Monitor
"""

import os
import json
import time
import psutil
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

# Basic network monitoring without scapy for simplicity
def run_network_guardian(duration: int = 30, audience: str = "family", 
                        threat_threshold: str = "medium", auto_block: bool = False):
    """Simple network guardian without complex dependencies"""
    
    print("Network Guardian - Starting Basic Analysis")
    print("=" * 50)
    print(f"Monitoring Duration: {duration} seconds")
    print(f"Target Audience: {audience}")
    print(f"Threat Threshold: {threat_threshold}")
    print(f"Auto-blocking: {'Enabled' if auto_block else 'Disabled'}")
    print("=" * 50)
    
    # Get initial network stats
    print("Collecting network statistics...")
    initial_stats = psutil.net_io_counters()
    initial_connections = len(psutil.net_connections(kind='inet'))
    
    # Wait for monitoring period
    print(f"Monitoring for {duration} seconds...")
    time.sleep(duration)
    
    # Get final network stats
    final_stats = psutil.net_io_counters()
    final_connections = len(psutil.net_connections(kind='inet'))
    
    # Calculate differences
    bytes_sent = final_stats.bytes_sent - initial_stats.bytes_sent
    bytes_recv = final_stats.bytes_recv - initial_stats.bytes_recv
    packets_sent = final_stats.packets_sent - initial_stats.packets_sent
    packets_recv = final_stats.packets_recv - initial_stats.packets_recv
    
    # Basic analysis
    total_bytes = bytes_sent + bytes_recv
    total_packets = packets_sent + packets_recv
    connection_change = final_connections - initial_connections
    
    print("\nNetwork Activity Analysis:")
    print(f"Total data transferred: {total_bytes/1024/1024:.2f} MB")
    print(f"Total packets: {total_packets}")
    print(f"Active connections: {final_connections}")
    print(f"Connection changes: {connection_change}")
    
    # Simple threat assessment
    threats = []
    risk_level = "low"
    
    # High data usage check
    if total_bytes > 50_000_000:  # 50MB
        threats.append({
            'type': 'high_data_usage',
            'severity': 'medium',
            'description': f'High network usage: {total_bytes/1024/1024:.1f} MB in {duration} seconds',
            'recommendation': 'Check for large downloads or streaming activity'
        })
        risk_level = "medium"
    
    # High packet count
    if total_packets > 10000:
        threats.append({
            'type': 'high_packet_count', 
            'severity': 'low',
            'description': f'High packet activity: {total_packets} packets',
            'recommendation': 'Monitor for potential scanning activity'
        })
    
    # Many new connections
    if connection_change > 20:
        threats.append({
            'type': 'many_new_connections',
            'severity': 'medium', 
            'description': f'{connection_change} new connections established',
            'recommendation': 'Review active network connections for suspicious activity'
        })
        risk_level = "medium"
    
    print(f"\nThreat Assessment:")
    print(f"Overall Risk Level: {risk_level.upper()}")
    print(f"Threats Detected: {len(threats)}")
    
    if threats:
        print("\nDetected Issues:")
        for i, threat in enumerate(threats, 1):
            print(f"{i}. {threat['type'].replace('_', ' ').title()}")
            print(f"   Severity: {threat['severity']}")
            print(f"   Description: {threat['description']}")
            print(f"   Recommendation: {threat['recommendation']}")
            print()
    else:
        print("No significant threats detected.")
    
    # Security recommendations
    print("Security Recommendations:")
    if risk_level == "medium":
        print("- Monitor network activity more frequently")
        print("- Check router logs for unusual connections")
        print("- Scan devices for malware")
    else:
        print("- Network activity appears normal")
        print("- Continue regular monitoring")
    
    print("- Keep router firmware updated")
    print("- Use strong WiFi passwords")
    print("- Enable router firewall")
    
    print("\nAnalysis Complete!")
    return {
        'duration': duration,
        'total_bytes': total_bytes,
        'total_packets': total_packets,
        'connections': final_connections,
        'risk_level': risk_level,
        'threats': threats
    }

if __name__ == "__main__":
    print("Simple Network Guardian")
    print("Basic Network Security Monitor")
    print()
    
    # Run basic analysis
    result = run_network_guardian(duration=30, audience="family")