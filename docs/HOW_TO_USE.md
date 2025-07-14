
# How to Use ForensIQ - Complete Guide

## Table of Contents

1. [Getting Started](#getting-started)
2. [Workflows & Processes](#workflows--processes)
3. [Use Cases & Scenarios](#use-cases--scenarios)
4. [User Stories](#user-stories)
5. [Step-by-Step Guides](#step-by-step-guides)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)

---

## Getting Started

### First Time Setup

1. **Launch ForensIQ**
   - Click the **Run** button in Replit
   - Wait for the application to start
   - Access via the web preview at your Replit URL

2. **Initial Navigation**
   - **Dashboard**: System overview and live metrics
   - **Analysis**: File and evidence analysis tools
   - **Devices**: Device detection and acquisition
   - **Network**: Network scanning and forensics
   - **Cloud**: Cloud forensics and container analysis
   - **Reports**: Investigation reports and timelines

3. **Quick Test**
   - Upload a test file in the Analysis section
   - View the generated report
   - Explore the dashboard metrics

---

## Workflows & Processes

### Core Investigation Workflow

#### 1. Evidence Collection Workflow
```
Start Investigation → Identify Sources → Acquire Evidence → Verify Integrity → Document Chain of Custody
```

**Steps:**
1. **Create Investigation Case**
   - Navigate to Dashboard
   - Click "New Investigation"
   - Enter case details and objectives

2. **Evidence Acquisition**
   - Go to Devices section
   - Scan for connected devices
   - Select acquisition type (logical/physical)
   - Execute acquisition with automated documentation

3. **Evidence Validation**
   - System automatically calculates MD5/SHA-256 hashes
   - Chain of custody is logged automatically
   - Evidence integrity is verified

#### 2. Analysis Workflow
```
Evidence Upload → Automated Analysis → Manual Review → Report Generation → Documentation
```

**Steps:**
1. **File Analysis**
   - Upload evidence files (max 16MB)
   - System performs automated analysis
   - Review metadata and extracted information

2. **Advanced Analysis**
   - AI-powered anomaly detection
   - Malware classification
   - Encryption analysis
   - Timeline reconstruction

3. **Cross-Reference Analysis**
   - Network analysis correlation
   - Device artifact matching
   - Timeline synchronization

#### 3. Reporting Workflow
```
Data Collection → Analysis Review → Report Generation → Quality Review → Documentation Export
```

**Steps:**
1. **Compile Findings**
   - Review all analysis results
   - Correlate evidence across modules
   - Identify key findings

2. **Generate Reports**
   - Navigate to Reports section
   - Select report type (Executive/Technical/Legal)
   - System generates comprehensive documentation

3. **Export and Share**
   - Download reports in multiple formats
   - Maintain chain of custody documentation

### Specialized Investigation Workflows

#### Cloud Forensics Workflow
```
Cloud Access → Data Acquisition → Container Analysis → Timeline Reconstruction → Reporting
```

#### Mobile Device Workflow
```
Device Detection → Bypass Security → Data Extraction → App Analysis → Social Media Recovery
```

#### Network Incident Workflow
```
Traffic Capture → PCAP Analysis → IOC Extraction → Threat Intelligence → Attribution
```

---

## Use Cases & Scenarios

### 1. Corporate Data Breach Investigation

**Scenario**: Company suspects insider threat with data exfiltration

**ForensIQ Workflow**:
1. **Initial Response**
   - Use Live Forensics for real-time monitoring
   - Capture volatile memory from suspect systems
   - Preserve network traffic logs

2. **Evidence Collection**
   - Acquire suspect workstation disk images
   - Extract mobile device data
   - Collect cloud service logs

3. **Analysis Process**
   - Timeline analysis to reconstruct events
   - Email and communication forensics
   - File access pattern analysis
   - Network traffic analysis for data transfers

4. **Intelligence Correlation**
   - Check IOCs against threat intelligence
   - Analyze behavioral patterns
   - Cross-reference with known attack signatures

**Expected Outcome**: Complete timeline of incident, identification of data accessed, evidence of exfiltration methods

### 2. Ransomware Attack Investigation

**Scenario**: Organization hit by ransomware, need to determine entry point and scope

**ForensIQ Workflow**:
1. **Immediate Analysis**
   - Use Sandbox Analysis for malware samples
   - Analyze encryption artifacts
   - Identify ransomware family

2. **Network Investigation**
   - PCAP analysis for C2 communications
   - Lateral movement tracking
   - Entry point identification

3. **System Forensics**
   - Memory analysis for fileless components
   - Registry analysis for persistence
   - File system timeline reconstruction

4. **Attribution**
   - Threat intelligence correlation
   - Campaign matching
   - TTPs analysis

**Expected Outcome**: Entry vector identification, attack timeline, scope assessment, attribution data

### 3. Mobile Device Investigation

**Scenario**: Employee suspected of corporate espionage using mobile devices

**ForensIQ Workflow**:
1. **Device Acquisition**
   - Physical/logical acquisition of mobile devices
   - Cloud backup extraction
   - SIM card forensics

2. **Communication Analysis**
   - WhatsApp, Telegram message recovery
   - Email forensics
   - Social media activity analysis

3. **Location Analysis**
   - GPS history reconstruction
   - Cell tower data analysis
   - Geofencing correlation

4. **App Forensics**
   - Installed app analysis
   - Data sharing patterns
   - Hidden app detection

**Expected Outcome**: Communication patterns, location timeline, evidence of data sharing

### 4. Cloud Infrastructure Compromise

**Scenario**: Suspicious activity detected in AWS/Azure environment

**ForensIQ Workflow**:
1. **Cloud Data Acquisition**
   - CloudTrail log collection
   - Container image analysis
   - Serverless function investigation

2. **Infrastructure Analysis**
   - Kubernetes pod forensics
   - Virtual machine analysis
   - Network flow investigation

3. **Access Analysis**
   - IAM credential analysis
   - Privilege escalation tracking
   - Multi-factor authentication bypass

4. **Impact Assessment**
   - Data exposure analysis
   - Service disruption assessment
   - Compliance impact evaluation

**Expected Outcome**: Attack vector, compromised resources, data exposure scope

### 5. Cryptocurrency Investigation

**Scenario**: Investigating cryptocurrency fraud and money laundering

**ForensIQ Workflow**:
1. **Wallet Analysis**
   - Bitcoin/Ethereum transaction tracing
   - Address clustering
   - Exchange interaction analysis

2. **Smart Contract Investigation**
   - DeFi protocol analysis
   - Contract vulnerability assessment
   - Transaction flow mapping

3. **Cross-Platform Correlation**
   - Multi-blockchain analysis
   - NFT authenticity verification
   - Mixer/tumbler detection

4. **Attribution**
   - Exchange KYC correlation
   - Social media linking
   - Traditional banking connections

**Expected Outcome**: Money trail documentation, wallet ownership attribution, violation evidence

---

## User Stories

### Digital Forensics Investigator

**As a** digital forensics investigator  
**I want to** quickly analyze suspect devices and files  
**So that** I can identify evidence of criminal activity  

**Acceptance Criteria**:
- Can upload and analyze files within 30 seconds
- Automatic hash calculation and chain of custody
- Comprehensive metadata extraction
- Detailed analysis reports

**ForensIQ Solution**: Analysis module with drag-and-drop upload, automated processing, and instant reporting

---

### Incident Response Team Lead

**As an** incident response team lead  
**I want to** coordinate multi-source evidence collection  
**So that** I can understand the full scope of a security incident  

**Acceptance Criteria**:
- Real-time monitoring capabilities
- Multiple evidence source integration
- Timeline correlation across sources
- Executive summary generation

**ForensIQ Solution**: Live Forensics dashboard with unified timeline and cross-source correlation

---

### Corporate Security Analyst

**As a** corporate security analyst  
**I want to** investigate potential insider threats  
**So that** I can protect company data and intellectual property  

**Acceptance Criteria**:
- Employee activity monitoring
- Email and communication analysis
- File access pattern analysis
- Risk scoring and alerting

**ForensIQ Solution**: AI Intelligence module with behavioral analysis and anomaly detection

---

### Law Enforcement Detective

**As a** law enforcement detective  
**I want to** extract evidence from mobile devices  
**So that** I can build a case against suspects  

**Acceptance Criteria**:
- Mobile device acquisition
- Deleted data recovery
- Communication reconstruction
- Location timeline analysis

**ForensIQ Solution**: Mobile & IoT Forensics with advanced acquisition and recovery capabilities

---

### Cybersecurity Consultant

**As a** cybersecurity consultant  
**I want to** analyze malware samples safely  
**So that** I can understand attack methods and provide recommendations  

**Acceptance Criteria**:
- Safe malware execution environment
- Behavioral analysis
- IOC extraction
- Threat classification

**ForensIQ Solution**: Sandbox Analysis with isolated execution and comprehensive reporting

---

### Compliance Officer

**As a** compliance officer  
**I want to** generate audit-ready forensic reports  
**So that** I can demonstrate regulatory compliance  

**Acceptance Criteria**:
- Standardized report formats
- Chain of custody documentation
- Detailed methodology documentation
- Regulatory framework alignment

**ForensIQ Solution**: Reports module with multiple format options and compliance templates

---

## Step-by-Step Guides

### Guide 1: Basic File Analysis

**Objective**: Analyze a suspicious file for malware indicators

**Steps**:
1. **Access Analysis Module**
   - Click "Analysis" in navigation
   - Select "File Analysis" tab

2. **Upload File**
   - Click "Choose File" button
   - Select file (max 16MB)
   - File uploads automatically

3. **Review Results**
   - MD5/SHA-256 hashes displayed
   - File metadata extracted
   - Malware scan results shown

4. **Generate Report**
   - Click "Generate Report"
   - Select report format
   - Download or view online

**Expected Time**: 2-5 minutes

### Guide 2: Mobile Device Investigation

**Objective**: Extract data from an Android device

**Steps**:
1. **Connect Device**
   - Enable USB debugging on Android device
   - Connect via USB cable
   - Navigate to "Devices" section

2. **Device Detection**
   - Click "Scan for Devices"
   - Select detected Android device
   - Choose acquisition type

3. **Data Acquisition**
   - Select data types to extract
   - Click "Start Acquisition"
   - Monitor progress bar

4. **Analyze Results**
   - Review extracted data
   - Examine app data and communications
   - Generate timeline report

**Expected Time**: 15-45 minutes (depending on device size)

### Guide 3: Network Incident Analysis

**Objective**: Investigate suspicious network activity

**Steps**:
1. **Network Scanning**
   - Go to "Network" section
   - Click "Start Network Scan"
   - Review discovered devices

2. **Traffic Analysis**
   - Navigate to "Network Analysis"
   - Upload PCAP file or use live capture
   - Analyze traffic patterns

3. **Threat Detection**
   - Review suspicious connections
   - Check IOCs against threat intelligence
   - Identify potential threats

4. **Documentation**
   - Generate network forensics report
   - Include IOCs and recommendations
   - Export for incident response

**Expected Time**: 10-30 minutes

### Guide 4: Cloud Environment Investigation

**Objective**: Investigate suspicious activity in cloud infrastructure

**Steps**:
1. **Cloud Connection**
   - Navigate to "Cloud Forensics"
   - Select cloud provider (AWS/Azure/GCP)
   - Configure API credentials

2. **Data Collection**
   - Select resource types to analyze
   - Choose time range for logs
   - Start automated collection

3. **Container Analysis**
   - Analyze Docker containers
   - Review Kubernetes pods
   - Examine serverless functions

4. **Report Generation**
   - Compile cloud forensics findings
   - Include security recommendations
   - Generate compliance report

**Expected Time**: 20-60 minutes

### Guide 5: Comprehensive Investigation

**Objective**: Complete multi-source investigation

**Steps**:
1. **Case Setup**
   - Create new investigation case
   - Define scope and objectives
   - Set up evidence tracking

2. **Evidence Collection**
   - Acquire device images
   - Collect network logs
   - Extract cloud data
   - Gather mobile device data

3. **Analysis Phase**
   - Run automated analysis on all evidence
   - Use AI Intelligence for anomaly detection
   - Perform timeline correlation

4. **Intelligence Integration**
   - Check findings against threat intelligence
   - Correlate with known campaigns
   - Perform attribution analysis

5. **Reporting**
   - Generate executive summary
   - Create technical analysis report
   - Document chain of custody
   - Prepare legal documentation

**Expected Time**: 2-8 hours (depending on scope)

---

## Best Practices

### Evidence Handling

1. **Always Verify Integrity**
   - Check file hashes before and after analysis
   - Maintain chain of custody documentation
   - Use write-blocking when possible

2. **Document Everything**
   - Record all actions taken
   - Note any anomalies or errors
   - Maintain detailed investigation logs

3. **Preserve Original Evidence**
   - Work with copies when possible
   - Store originals securely
   - Maintain multiple backup copies

### Analysis Methodology

1. **Start with Overview**
   - Use Dashboard for system overview
   - Identify key evidence sources
   - Plan analysis approach

2. **Use Multiple Analysis Methods**
   - Combine automated and manual analysis
   - Cross-reference findings across modules
   - Validate results with multiple tools

3. **Maintain Objectivity**
   - Follow evidence wherever it leads
   - Document negative results
   - Avoid confirmation bias

### Reporting Standards

1. **Clear and Concise**
   - Use plain language for executives
   - Include technical details in appendices
   - Provide actionable recommendations

2. **Comprehensive Documentation**
   - Include methodology
   - Document all evidence sources
   - Provide supporting screenshots

3. **Legal Considerations**
   - Ensure admissibility standards
   - Maintain chain of custody
   - Follow jurisdictional requirements

---

## Troubleshooting

### Common Issues

#### 1. File Upload Fails
**Problem**: Cannot upload files for analysis  
**Solution**:
- Check file size (max 16MB)
- Verify file is not corrupted
- Try different browser
- Check network connection

#### 2. Device Not Detected
**Problem**: Mobile device not showing in device list  
**Solution**:
- Enable USB debugging (Android)
- Install device drivers
- Check USB cable connection
- Restart device detection

#### 3. Analysis Appears Incomplete
**Problem**: Missing data in analysis results  
**Solution**:
- Wait for analysis to complete
- Check for error messages in console
- Retry analysis with different parameters
- Contact support if persistent

#### 4. Network Scan Empty
**Problem**: Network scan returns no devices  
**Solution**:
- Verify network connectivity
- Check IP range settings
- Ensure proper permissions
- Try different scan parameters

#### 5. Report Generation Fails
**Problem**: Cannot generate or download reports  
**Solution**:
- Check browser popup blockers
- Verify sufficient data for report
- Try different report format
- Clear browser cache

### Performance Optimization

1. **Large Files**
   - Split large files into smaller chunks
   - Use streaming analysis when available
   - Increase system resources if needed

2. **Network Analysis**
   - Limit PCAP file size
   - Use time-based filtering
   - Focus on specific protocols

3. **Device Analysis**
   - Use logical acquisition for faster results
   - Selective data extraction
   - Parallel processing when possible

### Getting Help

1. **Built-in Help**
   - Hover tooltips on interface elements
   - Context-sensitive help in each module
   - Error message explanations

2. **Documentation**
   - Check User Manual for detailed procedures
   - Review Technical Guide for advanced topics
   - Consult Feature Guide for capabilities

3. **Support Resources**
   - Submit issues through Admin portal
   - Check troubleshooting logs
   - Contact technical support team

---

## Workflow Integration

### Replit Workflows

ForensIQ integrates with Replit's workflow system for common tasks:

#### Available Workflows

1. **Server** (Default Run Button)
   - Starts the main ForensIQ application
   - Initializes all forensic modules
   - Sets up the web interface

2. **Custom Analysis Workflow**
   You can create custom workflows for specific investigation types:

```bash
# Example: Malware Analysis Workflow
python main.py --mode=malware_analysis
```

#### Creating Custom Workflows

1. **Access Workflows Pane**
   - Use Command + K and search "Workflows"
   - Or click the tools sidebar menu

2. **Create New Workflow**
   - Click "+ New Workflow"
   - Name: "Quick Malware Scan"
   - Mode: Sequential

3. **Add Tasks**
   - Execute Shell Command: `python -c "from app import start_malware_scan; start_malware_scan()"`
   - Install Packages: (if additional tools needed)

### Integration with External Tools

ForensIQ can be integrated with external forensic tools through custom workflows:

1. **Evidence Processing Pipeline**
2. **Automated Report Distribution**
3. **Threat Intelligence Updates**
4. **Backup and Archival**

---

**Complete Guide**: You now have comprehensive documentation for using ForensIQ in real-world forensic investigations!

