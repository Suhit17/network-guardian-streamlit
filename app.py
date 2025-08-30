#!/usr/bin/env python3
"""
Network Guardian - Streamlit Cloud Deployment Version
Optimized for cloud deployment with limited system access
"""

import streamlit as st
import time
import json
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np

# Set page config
st.set_page_config(
    page_title="Network Guardian",
    page_icon="🛡️",
    layout="wide"
)

# Title and header
st.title("🛡️ Network Guardian")
st.markdown("**Network Security Monitoring System**")

# Create tabs for different sections
tab1, tab2, tab3, tab4 = st.tabs(["🚀 Demo", "✨ Features", "📋 Requirements", "🎯 How to Use"])

with tab1:
    st.markdown("---")
    
    # Cloud deployment notice
    st.info("📊 **Demo Mode**: This is a demonstration version running on Streamlit Cloud. Full network monitoring capabilities are available when running locally.")
    
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
    st.sidebar.header("📊 Demo Configuration")
    duration = st.sidebar.slider("Demo Duration (seconds)", 5, 30, 10)
    audience = st.sidebar.selectbox("Target Audience", ["family", "business", "personal"])
    threat_threshold = st.sidebar.selectbox("Threat Threshold", ["low", "medium", "high"])
    auto_block = st.sidebar.checkbox("Enable Auto-blocking", value=False)

    # Demo simulation function
    def run_demo_analysis(duration: int, audience: str, threat_threshold: str, auto_block: bool):
        """Run simulated network analysis for demo purposes"""
        
        # Create progress bar
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Simulate monitoring for specified duration
        for i in range(duration):
            progress_bar.progress((i + 1) / duration)
            status_text.text(f'Demo analysis... {duration - i - 1} seconds remaining')
            time.sleep(1)
        
        status_text.text('Demo analysis complete!')
        
        # Generate realistic demo data
        np.random.seed(42)  # For consistent demo results
        
        # Simulate network activity
        bytes_sent = np.random.randint(1000000, 10000000)  # 1-10 MB
        bytes_recv = np.random.randint(5000000, 50000000)  # 5-50 MB
        packets_sent = np.random.randint(1000, 5000)
        packets_recv = np.random.randint(2000, 10000)
        connections = np.random.randint(15, 35)
        connection_change = np.random.randint(-5, 15)
        
        total_bytes = bytes_sent + bytes_recv
        total_packets = packets_sent + packets_recv
        
        # Simulate threat assessment
        threats = []
        risk_level = "low"
        
        # High data usage check
        if total_bytes > 30_000_000:  # 30MB
            threats.append({
                'type': 'High Data Usage',
                'severity': 'medium',
                'description': f'Elevated network usage: {total_bytes/1024/1024:.1f} MB detected',
                'recommendation': 'Monitor for large downloads or streaming activity'
            })
            risk_level = "medium"
        
        # High packet count
        if total_packets > 8000:
            threats.append({
                'type': 'High Packet Activity', 
                'severity': 'low',
                'description': f'Increased packet activity: {total_packets:,} packets',
                'recommendation': 'Verify normal application behavior'
            })
        
        # Connection changes
        if connection_change > 10:
            threats.append({
                'type': 'Connection Spike',
                'severity': 'medium', 
                'description': f'{connection_change} new connections established',
                'recommendation': 'Review active applications and services'
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
            'connections': connections,
            'connection_change': connection_change,
            'risk_level': risk_level,
            'threats': threats,
            'timestamp': datetime.now().isoformat()
        }

    # Main interface
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Network Monitoring Demo")
        
        if st.button("🚀 Start Demo Analysis", type="primary"):
            st.markdown("---")
            
            # Run demo analysis
            with st.spinner('Running network analysis simulation...'):
                results = run_demo_analysis(duration, audience, threat_threshold, auto_block)
            
            # Display results
            st.success("Demo Analysis Complete!")
            
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
                
                fig_pie = px.pie(data_df, values='Bytes', names='Direction', 
                                title='Data Transfer Distribution')
                st.plotly_chart(fig_pie, use_container_width=True)
            
            with col_chart2:
                # Packet distribution
                packet_df = pd.DataFrame({
                    'Direction': ['Sent', 'Received'],
                    'Packets': [results['packets_sent'], results['packets_recv']]
                })
                
                fig_bar = px.bar(packet_df, x='Direction', y='Packets',
                               title='Packet Distribution')
                st.plotly_chart(fig_bar, use_container_width=True)
            
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
        
        st.subheader("📊 Demo Info")
        st.markdown("""
        **🌐 Cloud Limitations:**
        - Simulated network data
        - Limited system access
        - Demo functionality only
        
        **🏠 Local Installation:**
        - Real network monitoring
        - Full system integration
        - Advanced threat detection
        """)
        
        st.subheader("🔗 Links")
        st.markdown("""
        - [GitHub Repository](https://github.com/Suhit17/network-guardian-crew)
        - [Local Installation Guide](#)
        - [Documentation](#)
        """)

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
    
    st.subheader("☁️ Cloud vs Local Deployment")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**🌐 Streamlit Cloud**")
        st.markdown("""
        - Demo functionality
        - Simulated network data
        - Limited system access
        - Easy sharing and access
        - No installation required
        """)
    
    with col2:
        st.markdown("**🏠 Local Installation**")
        st.markdown("""
        - Full network monitoring
        - Real system integration
        - Administrative privileges
        - Complete feature set
        - Advanced threat detection
        """)

with tab4:
    st.header("🎯 How to Use")
    
    st.subheader("☁️ Cloud Demo (Current)")
    st.markdown("""
    1. **Configure Settings**: Use the sidebar to adjust demo parameters
    2. **Optional API Key**: Add Google Gemini API key for enhanced features
    3. **Run Demo**: Click "🚀 Start Demo Analysis" to see simulated results
    4. **Explore Features**: Navigate through tabs to learn about capabilities
    """)
    
    st.subheader("🏠 Local Installation")
    
    st.markdown("**🚀 Quick Setup**")
    st.code("""
# Clone the repository
git clone https://github.com/Suhit17/network-guardian-crew

# Install dependencies
pip install -r requirements.txt

# Run locally
streamlit run streamlit_app.py
""", language="bash")
    
    st.subheader("⚙️ Configuration Options")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **⏱️ Monitoring Duration**
        - **Cloud**: 5-30 seconds (demo)
        - **Local**: 10-300 seconds (real monitoring)
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
        - **True**: Automatic threat response (local only)
        """)
    
    st.subheader("🔗 Getting Started Locally")
    
    st.markdown("""
    **For full network monitoring capabilities:**
    
    1. **Download**: Clone from [GitHub Repository](https://github.com/Suhit17/network-guardian-crew)
    2. **Install**: Run `pip install -r requirements.txt`
    3. **Configure**: Set up Google API key (optional)
    4. **Launch**: Run `streamlit run streamlit_app.py`
    5. **Monitor**: Start real-time network analysis
    
    **Key Differences:**
    - **Real Network Data**: Actual system monitoring vs simulated demo
    - **Extended Duration**: Monitor for minutes vs seconds
    - **System Integration**: Full access to network interfaces and processes
    - **Advanced Features**: Complete threat detection and response capabilities
    """)

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: gray;'>"
    "Network Guardian • Network Security Monitoring System<br>"
    "For educational and defensive security purposes only<br>"
    "<a href='https://github.com/Suhit17/network-guardian-crew' target='_blank'>GitHub Repository</a>"
    "</div>", 
    unsafe_allow_html=True
)