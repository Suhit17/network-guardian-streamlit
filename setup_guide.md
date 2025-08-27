# Network Guardian Crew Setup Guide

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
```bash
python network_guardian_crew.py
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