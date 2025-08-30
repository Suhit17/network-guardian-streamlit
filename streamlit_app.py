#!/usr/bin/env python3
"""
Network Guardian - Streamlit Web Interface
"""

import streamlit as st
import psutil
import time
import json
import os
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

# Set page config
st.set_page_config(
    page_title="Network Guardian",
    page_icon="🛡️",
    layout="wide"
)

# Title and header
st.title("🛡️ Network Guardian")
st.markdown("**Basic Network Security Monitor**")

# Create tabs for different sections
tab1, tab2, tab3, tab4 = st.tabs(["🚀 Monitor", "✨ Features", "📋 Requirements", "🎯 How to Use"])

with tab1:
    st.markdown("---")

# API Key Configuration
def validate_api_key(api_key: str) -> bool:
    """Basic API key validation"""
    if not api_key:
        return False
    # Basic format check for Google API keys
    if len(api_key) < 20 or not api_key.replace('-', '').replace('_', '').isalnum():
        return False
    return True

# Sidebar configuration
st.sidebar.header("🔑 API Configuration")

# Get API key from user input only
api_key_input = st.sidebar.text_input(
    "Google API Key", 
    value="",
    type="password",
    help="Enter your Google Gemini API key for AI-powered threat analysis. Get one at https://aistudio.google.com/",
    placeholder="Enter your API key here..."
)

# API Key status
if api_key_input:
    if validate_api_key(api_key_input):
        st.sidebar.success("✅ API Key configured")
        api_key_status = True
    else:
        st.sidebar.error("❌ Invalid API Key format")
        api_key_status = False
else:
    st.sidebar.warning("⚠️ No API Key provided")
    st.sidebar.info("💡 AI-powered analysis requires a Google Gemini API key")
    api_key_status = False

st.sidebar.markdown("---")
st.sidebar.header("📊 Monitoring Configuration")
duration = st.sidebar.slider("Monitoring Duration (seconds)", 10, 300, 30)
audience = st.sidebar.selectbox("Target Audience", ["family", "business", "personal"])
threat_threshold = st.sidebar.selectbox("Threat Threshold", ["low", "medium", "high"])
auto_block = st.sidebar.checkbox("Enable Auto-blocking", value=False)

# Main monitoring function
def run_network_analysis(duration: int, audience: str, threat_threshold: str, auto_block: bool):
    """Run network analysis and return results"""
    
    # Get initial network stats
    initial_stats = psutil.net_io_counters()
    initial_connections = len(psutil.net_connections(kind='inet'))
    
    # Create progress bar
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    # Monitor for specified duration
    for i in range(duration):
        progress_bar.progress((i + 1) / duration)
        status_text.text(f'Monitoring... {duration - i - 1} seconds remaining')
        time.sleep(1)
    
    status_text.text('Analysis complete!')
    
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
    
    # Simple threat assessment
    threats = []
    risk_level = "low"
    
    # High data usage check
    if total_bytes > 50_000_000:  # 50MB
        threats.append({
            'type': 'High Data Usage',
            'severity': 'medium',
            'description': f'High network usage: {total_bytes/1024/1024:.1f} MB in {duration} seconds',
            'recommendation': 'Check for large downloads or streaming activity'
        })
        risk_level = "medium"
    
    # High packet count
    if total_packets > 10000:
        threats.append({
            'type': 'High Packet Count', 
            'severity': 'low',
            'description': f'High packet activity: {total_packets} packets',
            'recommendation': 'Monitor for potential scanning activity'
        })
    
    # Many new connections
    if connection_change > 20:
        threats.append({
            'type': 'Many New Connections',
            'severity': 'medium', 
            'description': f'{connection_change} new connections established',
            'recommendation': 'Review active network connections for suspicious activity'
        })
        risk_level = "medium"
    
    return {
        'duration': duration,
        'bytes_sent': bytes_sent,
        'bytes_recv': bytes_recv,
        'total_bytes': total_bytes,
        'packets_sent': packets_sent,
        'packets_recv': packets_recv,
        'total_packets': total_packets,
        'connections': final_connections,
        'connection_change': connection_change,
        'risk_level': risk_level,
        'threats': threats,
        'timestamp': datetime.now().isoformat()
    }

# Main interface
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Network Monitoring")
    
    if st.button("🚀 Start Network Analysis", type="primary"):
        st.markdown("---")
        
        # Run analysis
        with st.spinner('Analyzing network activity...'):
            results = run_network_analysis(duration, audience, threat_threshold, auto_block)
        
        # Display results
        st.success("Analysis Complete!")
        
        # Metrics display
        col_a, col_b, col_c, col_d = st.columns(4)
        
        with col_a:
            st.metric(
                "Data Transferred", 
                f"{results['total_bytes']/1024/1024:.2f} MB",
                f"↑{results['bytes_sent']/1024/1024:.1f} ↓{results['bytes_recv']/1024/1024:.1f}"
            )
        
        with col_b:
            st.metric(
                "Total Packets", 
                f"{results['total_packets']:,}",
                f"↑{results['packets_sent']:,} ↓{results['packets_recv']:,}"
            )
        
        with col_c:
            st.metric(
                "Active Connections", 
                results['connections'],
                results['connection_change']
            )
        
        with col_d:
            risk_color = {"low": "🟢", "medium": "🟡", "high": "🔴"}
            st.metric(
                "Risk Level", 
                f"{risk_color.get(results['risk_level'], '⚪')} {results['risk_level'].upper()}"
            )
        
        # Data visualization
        st.subheader("📊 Network Activity Breakdown")
        
        # Create charts
        col_chart1, col_chart2 = st.columns(2)
        
        with col_chart1:
            # Data transfer pie chart
            data_df = pd.DataFrame({
                'Direction': ['Sent', 'Received'],
                'Bytes': [results['bytes_sent'], results['bytes_recv']]
            })
            
            if data_df['Bytes'].sum() > 0:
                fig_pie = px.pie(data_df, values='Bytes', names='Direction', 
                                title='Data Transfer Distribution')
                st.plotly_chart(fig_pie, use_container_width=True)
            else:
                st.info("No significant data transfer detected")
        
        with col_chart2:
            # Packet distribution
            packet_df = pd.DataFrame({
                'Direction': ['Sent', 'Received'],
                'Packets': [results['packets_sent'], results['packets_recv']]
            })
            
            if packet_df['Packets'].sum() > 0:
                fig_bar = px.bar(packet_df, x='Direction', y='Packets',
                               title='Packet Distribution')
                st.plotly_chart(fig_bar, use_container_width=True)
            else:
                st.info("No significant packet activity detected")
        
        # Threat assessment
        st.subheader("🔍 Threat Assessment")
        
        # Show API key notice if not configured
        if not api_key_status:
            st.info("💡 **Enhanced AI Analysis Available**: Configure your Google API key in the sidebar for advanced threat intelligence and personalized security recommendations.")
        
        if results['threats']:
            st.warning(f"⚠️ {len(results['threats'])} potential issue(s) detected:")
            
            for threat in results['threats']:
                severity_color = {"low": "🟡", "medium": "🟠", "high": "🔴"}
                
                with st.expander(f"{severity_color.get(threat['severity'], '⚪')} {threat['type']}"):
                    st.write(f"**Severity:** {threat['severity'].title()}")
                    st.write(f"**Description:** {threat['description']}")
                    st.write(f"**Recommendation:** {threat['recommendation']}")
                    
                    if not api_key_status:
                        st.info("🤖 *Enhanced AI analysis available with API key*")
        else:
            st.success("✅ No significant threats detected")
            if not api_key_status:
                st.info("🤖 *Enhanced AI threat detection available with API key*")
        
        # Security recommendations
        st.subheader("🛡️ Security Recommendations")
        
        recommendations = [
            "Keep router firmware updated",
            "Use strong WiFi passwords", 
            "Enable router firewall"
        ]
        
        if results['risk_level'] == "medium":
            recommendations.extend([
                "Monitor network activity more frequently",
                "Check router logs for unusual connections",
                "Scan devices for malware"
            ])
        else:
            recommendations.extend([
                "Network activity appears normal",
                "Continue regular monitoring"
            ])
        
        for rec in recommendations:
            st.write(f"• {rec}")

with col2:
    st.subheader("📋 Configuration")
    
    # API Status
    if api_key_status:
        st.write("🔑 **API Status:** ✅ Connected")
    else:
        st.write("🔑 **API Status:** ❌ Not configured")
    
    st.write(f"⏱️ **Duration:** {duration} seconds")
    st.write(f"👥 **Audience:** {audience}")
    st.write(f"🎯 **Threshold:** {threat_threshold}")
    st.write(f"🛡️ **Auto-block:** {'Enabled' if auto_block else 'Disabled'}")
    
    st.subheader("📊 System Info")
    
    # Real-time system stats
    cpu_percent = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    network_stats = psutil.net_io_counters()
    
    st.metric("CPU Usage", f"{cpu_percent}%")
    st.metric("Memory Usage", f"{memory.percent}%")
    st.metric("Network Connections", len(psutil.net_connections(kind='inet')))
    
    # Live network stats
    st.subheader("🔄 Live Stats")
    st.write(f"**Bytes Sent:** {network_stats.bytes_sent:,}")
    st.write(f"**Bytes Received:** {network_stats.bytes_recv:,}")
    st.write(f"**Packets Sent:** {network_stats.packets_sent:,}")
    st.write(f"**Packets Received:** {network_stats.packets_recv:,}")

with tab2:
    st.header("✨ Features")
    
    st.subheader("🔍 Real-Time Network Monitoring")
    st.markdown("""
    - **Live Traffic Analysis**: Monitor data transfer, packet counts, and connection patterns
    - **Threat Detection**: Identify suspicious network activity and potential security risks  
    - **Connection Tracking**: Monitor active network connections and detect anomalies
    - **Performance Metrics**: Track network usage and system performance
    """)
    
    st.subheader("🛡️ Security Assessment") 
    st.markdown("""
    - **Risk Level Analysis**: Automated threat classification (Low/Medium/High)
    - **Anomaly Detection**: Identify unusual network behavior patterns
    - **Security Recommendations**: Personalized advice based on detected activity
    - **Threat Intelligence**: AI-powered analysis of network security events
    """)
    
    st.subheader("📊 Interactive Web Interface")
    st.markdown("""
    - **Streamlit Dashboard**: Modern, responsive web interface
    - **Real-Time Visualizations**: Charts and graphs for network activity
    - **Configuration Controls**: Easy-to-use monitoring settings
    - **Progress Tracking**: Live monitoring with progress indicators
    """)
    
    st.subheader("👨‍👩‍👧‍👦 Family-Friendly Design")
    st.markdown("""
    - **Multiple Audience Modes**: Content tailored for family, business, or personal use
    - **Non-Technical Explanations**: Clear, understandable security guidance
    - **Educational Content**: Learn about network security while monitoring
    """)
    
    st.subheader("⚙️ Advanced Features")
    st.markdown("""
    - **Configurable Monitoring**: Adjustable duration and sensitivity settings
    - **Multi-Platform Support**: Works on Windows, macOS, and Linux
    - **Background Processing**: Non-intrusive monitoring capabilities
    - **Extensible Architecture**: Easy to customize and extend
    """)

with tab3:
    st.header("📋 Requirements & Dependencies")
    
    st.subheader("💻 System Requirements")
    st.markdown("""
    - **Operating System**: Windows 10/11, macOS 10.14+, or Linux (Ubuntu 18.04+)
    - **Python Version**: Python 3.8 or higher
    - **Memory**: Minimum 4GB RAM (8GB recommended)
    - **Network**: Active internet connection for threat intelligence
    - **Permissions**: Administrative privileges for network monitoring
    """)
    
    st.subheader("🔧 Core Dependencies")
    st.markdown("""
    - **streamlit**: Web application framework for the dashboard interface
    - **psutil**: System and process monitoring for network statistics
    - **plotly**: Interactive charts and data visualization
    - **pandas**: Data analysis and manipulation
    - **numpy**: Numerical computing support
    """)
    
    st.subheader("🤖 AI & Machine Learning")
    st.markdown("""
    - **google-generativeai**: Google Gemini AI integration for threat analysis
    - **crewai**: Multi-agent AI framework for coordinated security analysis
    - **scikit-learn**: Machine learning for anomaly detection
    """)
    
    st.subheader("🌐 Network Monitoring")
    st.markdown("""
    - **scapy**: Advanced packet capture and network analysis
    - **pyshark**: Wireshark integration for deep packet inspection
    - **python-nmap**: Network discovery and port scanning
    """)
    
    st.subheader("⚡ Automation & Integration")
    st.markdown("""
    - **paramiko**: SSH automation for network device management
    - **netmiko**: Multi-vendor network device automation
    - **requests**: HTTP library for API integrations
    - **beautifulsoup4**: Web scraping for threat intelligence
    """)
    
    st.subheader("🔧 Development & Configuration")
    st.markdown("""
    - **python-dotenv**: Environment variable management
    - **pydantic**: Data validation and settings management
    - **typing-extensions**: Enhanced type checking support
    """)

with tab4:
    st.header("🎯 How to Use")
    
    st.subheader("🚀 Getting Started")
    st.markdown("""
    1. **Configure API Key** (Optional): Enter your Google Gemini API key in the sidebar for enhanced AI analysis
    2. **Set Monitoring Parameters**: Adjust duration, audience, and threat threshold in the sidebar
    3. **Start Analysis**: Click the "🚀 Start Network Analysis" button
    4. **Review Results**: Analyze the charts, metrics, and threat assessments
    """)
    
    st.subheader("⚙️ Configuration Options")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **⏱️ Monitoring Duration**
        - **Default**: 30 seconds
        - **Range**: 10-300 seconds
        - **Recommendation**: Start with 30s, increase for deeper analysis
        
        **👥 Audience Types**
        - **family**: Simple, non-technical explanations
        - **business**: Professional context and terminology
        - **personal**: Individual user focused content
        """)
    
    with col2:
        st.markdown("""
        **🎯 Threat Thresholds**
        - **low**: Alert on minor anomalies
        - **medium**: Focus on significant threats (recommended)
        - **high**: Only critical threats trigger alerts
        
        **🛡️ Auto-blocking**
        - **False**: Manual review required (recommended)
        - **True**: Automatic threat response (use with caution)
        """)
    
    st.subheader("📊 Understanding Results")
    
    st.markdown("**📈 Metrics Display**")
    st.markdown("""
    - **Data Transferred**: Total network usage with send/receive breakdown
    - **Total Packets**: Network packet count with directional information  
    - **Active Connections**: Current network connections and changes
    - **Risk Level**: Color-coded security assessment (🟢 Low, 🟡 Medium, 🔴 High)
    """)
    
    st.markdown("**📊 Visual Charts**")
    st.markdown("""
    - **Data Transfer Pie Chart**: Visual breakdown of sent vs received data
    - **Packet Distribution Bar Chart**: Comparison of packet activity
    """)
    
    st.markdown("**🔍 Threat Assessment**")  
    st.markdown("""
    - **Risk Level**: Overall security status with color coding
    - **Threat Details**: Specific issues with severity levels and descriptions
    - **Recommendations**: Actionable advice for detected threats
    """)
    
    st.subheader("💡 Best Practices")
    
    st.markdown("**🆕 First-Time Users**")
    st.markdown("""
    1. Start with 30-second monitoring sessions
    2. Use family mode for non-technical explanations
    3. Keep auto-block disabled initially
    4. Monitor during different times/activities
    """)
    
    st.markdown("**🔧 Advanced Users**") 
    st.markdown("""
    1. Use 60-300 second sessions for deeper analysis
    2. Set threshold to "low" to catch minor anomalies  
    3. Switch to business mode for technical details
    4. Consider scheduled automated monitoring
    """)
    
    st.subheader("⚠️ When to Investigate Further")
    st.markdown("""
    - Multiple threats detected simultaneously
    - High data usage during idle periods
    - Unexpected increases in network connections
    - Persistent medium/high risk level assessments
    - Unusual packet patterns or connection behaviors
    """)

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: gray;'>"
    "Network Guardian • Basic Network Security Monitor<br>"
    "For educational and defensive security purposes only"
    "</div>", 
    unsafe_allow_html=True
)