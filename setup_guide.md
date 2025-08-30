# Network Guardian Crew Setup Guide

## 📖 Overview

Network Guardian Crew is a comprehensive home network security monitoring system that provides real-time threat detection, analysis, and family-friendly security education. It combines AI-powered threat assessment with an intuitive web interface for both technical and non-technical users.

## ✨ Features

### 🔍 Real-Time Network Monitoring
- **Live Traffic Analysis**: Monitor data transfer, packet counts, and connection patterns
- **Threat Detection**: Identify suspicious network activity and potential security risks
- **Connection Tracking**: Monitor active network connections and detect anomalies
- **Performance Metrics**: Track network usage and system performance

### 🛡️ Security Assessment
- **Risk Level Analysis**: Automated threat classification (Low/Medium/High)
- **Anomaly Detection**: Identify unusual network behavior patterns
- **Security Recommendations**: Personalized advice based on detected activity
- **Threat Intelligence**: AI-powered analysis of network security events

### 📊 Interactive Web Interface
- **Streamlit Dashboard**: Modern, responsive web interface
- **Real-Time Visualizations**: Charts and graphs for network activity
- **Configuration Controls**: Easy-to-use monitoring settings
- **Progress Tracking**: Live monitoring with progress indicators

### 👨‍👩‍👧‍👦 Family-Friendly Design
- **Multiple Audience Modes**: Content tailored for family, business, or personal use
- **Non-Technical Explanations**: Clear, understandable security guidance
- **Educational Content**: Learn about network security while monitoring

### ⚙️ Advanced Features
- **Configurable Monitoring**: Adjustable duration and sensitivity settings
- **Multi-Platform Support**: Works on Windows, macOS, and Linux
- **Background Processing**: Non-intrusive monitoring capabilities
- **Extensible Architecture**: Easy to customize and extend

## 📋 Requirements & Dependencies

### System Requirements
- **Operating System**: Windows 10/11, macOS 10.14+, or Linux (Ubuntu 18.04+)
- **Python Version**: Python 3.8 or higher
- **Memory**: Minimum 4GB RAM (8GB recommended)
- **Network**: Active internet connection for threat intelligence
- **Permissions**: Administrative privileges for network monitoring

### Core Dependencies
- **streamlit**: Web application framework for the dashboard interface
- **psutil**: System and process monitoring for network statistics
- **plotly**: Interactive charts and data visualization
- **pandas**: Data analysis and manipulation
- **numpy**: Numerical computing support

### AI & Machine Learning
- **google-generativeai**: Google Gemini AI integration for threat analysis
- **crewai**: Multi-agent AI framework for coordinated security analysis
- **scikit-learn**: Machine learning for anomaly detection

### Network Monitoring
- **scapy**: Advanced packet capture and network analysis
- **pyshark**: Wireshark integration for deep packet inspection
- **python-nmap**: Network discovery and port scanning

### Automation & Integration
- **paramiko**: SSH automation for network device management
- **netmiko**: Multi-vendor network device automation
- **requests**: HTTP library for API integrations
- **beautifulsoup4**: Web scraping for threat intelligence

### Development & Configuration
- **python-dotenv**: Environment variable management
- **pydantic**: Data validation and settings management
- **typing-extensions**: Enhanced type checking support

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Get Google Gemini API Key
1. Go to [Google AI Studio](https://aistudio.google.com/)
2. Create a new API key
3. Copy the key for the next step

### 3. Configure Environment
1. Copy the `.env` file and rename it to `.env`
2. Replace `your_gemini_api_key_here` with your actual API key:
```bash
GOOGLE_API_KEY=your_actual_api_key_here
```

### 4. Run the Network Guardian

#### Option A: Streamlit Web Interface (Recommended)
```bash
streamlit run streamlit_app.py
```
Then open your browser to: http://localhost:8501

#### Option B: Command Line Interface
```bash
python simple_network_guardian.py
```

## 🎯 How to Use

### Web Interface (Streamlit)

#### Getting Started
1. **Launch the Application**
   ```bash
   streamlit run streamlit_app.py
   ```

2. **Access the Dashboard**
   - Open your web browser
   - Navigate to `http://localhost:8501`
   - The Network Guardian dashboard will load

#### Using the Dashboard

**Configuration Panel (Sidebar)**
- **Monitoring Duration**: Set how long to monitor (10-300 seconds)
- **Target Audience**: Choose explanation level (family/business/personal)
- **Threat Threshold**: Set sensitivity (low/medium/high)
- **Auto-blocking**: Enable/disable automatic threat response

**Main Dashboard**
1. **Configure Settings**: Adjust monitoring parameters in the sidebar
2. **Start Analysis**: Click "🚀 Start Network Analysis" button
3. **Monitor Progress**: Watch the real-time progress bar
4. **Review Results**: Analyze charts, metrics, and threat assessments

**Understanding the Results**

**📊 Metrics Display**
- **Data Transferred**: Total network usage with send/receive breakdown
- **Total Packets**: Network packet count with directional information
- **Active Connections**: Current network connections and changes
- **Risk Level**: Color-coded security assessment (🟢 Low, 🟡 Medium, 🔴 High)

**📈 Visual Charts**
- **Data Transfer Pie Chart**: Visual breakdown of sent vs received data
- **Packet Distribution Bar Chart**: Comparison of packet activity

**🔍 Threat Assessment**
- **Risk Level**: Overall security status
- **Threat Details**: Specific issues detected with:
  - Severity level (color-coded)
  - Detailed description
  - Recommended actions

**🛡️ Security Recommendations**
- Contextual advice based on your network activity
- General security best practices
- Specific actions for detected threats

### Command Line Interface

#### Basic Usage
```bash
python simple_network_guardian.py
```

#### Programmatic Usage
```python
from simple_network_guardian import run_network_guardian

# Basic monitoring
results = run_network_guardian(
    duration=30,
    audience="family",
    threat_threshold="medium",
    auto_block=False
)

# Review results
print(f"Risk Level: {results['risk_level']}")
print(f"Threats Found: {len(results['threats'])}")
```

### Best Practices

#### First-Time Users
1. **Start Small**: Begin with 30-second monitoring sessions
2. **Use Family Mode**: Start with non-technical explanations
3. **Disable Auto-block**: Review threats manually initially
4. **Monitor Regularly**: Run analysis during different times/activities

#### Advanced Users
1. **Extend Duration**: Use 60-300 second sessions for deeper analysis
2. **Lower Thresholds**: Set to "low" to catch minor anomalies
3. **Technical Mode**: Switch to technical explanations for detailed info
4. **Schedule Monitoring**: Set up regular automated scans

#### Network Activity Interpretation

**Normal Activity Indicators**
- Steady, moderate data transfer
- Consistent packet rates
- Stable connection counts
- Low risk level assessment

**Potential Concern Indicators**
- Sudden spikes in data usage
- Unusual packet patterns
- Many new connections
- Medium/high risk assessment

**When to Investigate Further**
- Multiple threats detected
- High data usage during idle periods
- Unexpected connection increases
- Persistent medium/high risk levels

### Monitoring Scenarios

#### Daily Monitoring
```python
# Morning baseline check
run_network_guardian(duration=30, audience="family")
```

#### Suspicious Activity Investigation
```python
# Extended analysis with technical details
run_network_guardian(
    duration=120, 
    audience="technical",
    threat_threshold="low"
)
```

#### Family Internet Safety Check
```python
# Family-friendly monitoring with explanations
run_network_guardian(
    duration=60,
    audience="family", 
    threat_threshold="medium"
)
```

## 🛡️ How It Works

### Agent Structure

**1. Traffic Monitor Agent** 🕵️
- Monitors network traffic using Scapy
- Detects unusual patterns and connections
- Collects traffic statistics

**2. Threat Explainer Agent** 🎯  
- Analyzes traffic data for security threats
- Translates technical issues into plain language
- Assesses risk levels

**3. Action Enforcer Agent** ⚡
- Takes protective actions based on threats
- Can block IPs or isolate devices
- Documents all security actions

**4. Security Coach Agent** 🎓
- Provides personalized security education
- Creates family-friendly guidance
- Suggests security improvements

### Simple Usage Examples

```python
# Basic 30-second analysis
run_network_guardian()

# Extended monitoring with auto-actions
run_network_guardian(
    duration=120,
    auto_block=True,
    threat_threshold="medium"
)

# Technical audience analysis
run_network_guardian(
    duration=60,
    audience="technical",
    threat_threshold="low"
)
```

## 🔧 Configuration Options

### Monitoring Duration
- **Default**: 30 seconds
- **Range**: 10-300 seconds
- **Recommendation**: Start with 30s, increase for deeper analysis

### Audience Types
- **family**: Simple, non-technical explanations
- **technical**: Detailed technical information
- **children**: Very simple, age-appropriate language

### Threat Thresholds
- **low**: Alert on minor anomalies
- **medium**: Focus on significant threats (recommended)
- **high**: Only critical threats trigger actions

### Auto-blocking
- **False**: Manual review required (recommended for testing)
- **True**: Automatic threat blocking (use with caution)

## 📊 Example Output

The system will provide:

1. **Traffic Analysis**: Packet counts, data usage, connection patterns
2. **Threat Assessment**: Risk levels and specific threats found
3. **Security Actions**: Actions taken or recommended
4. **Education Content**: Personalized security guidance

## 🛠️ Troubleshooting

### Common Issues

**"No packets captured"**
- Run as administrator/sudo for packet capture
- Check network interface availability
- Verify Scapy installation

**"API Key Error"**  
- Verify Google API key in .env file
- Check API key permissions and quotas
- Ensure .env file is in the same directory

**"Permission Denied"**
- Network monitoring requires elevated privileges
- Run with sudo on Linux/Mac or as Administrator on Windows

### System Requirements

- **Python**: 3.8 or higher
- **OS**: Linux, macOS, or Windows
- **Privileges**: Administrative/root access for network monitoring
- **Network**: Active internet connection for threat intelligence

## 🔒 Security Notes

- All blocking actions are **simulated by default** for safety
- The system logs but doesn't execute actual firewall changes
- To enable real blocking, modify the `SecurityController` tool
- Always test in a safe environment first

## 📈 Extending the System

### Adding New Tools
1. Create a new tool class inheriting from `BaseTool`
2. Implement the `_run()` method
3. Add to the appropriate agent's tools list

### Custom Threat Detection
1. Modify `ThreatAnalyzer._run()` method
2. Add new threat patterns and detection logic
3. Update severity levels and recommendations

### Enhanced Education Content
1. Extend `EducationProvider` with new topics
2. Add audience-specific content variations
3. Include interactive elements or links

## 🆘 Support

For issues or questions:
1. Check the troubleshooting section above
2. Review CrewAI documentation
3. Verify all dependencies are installed correctly
4. Ensure API keys are properly configured