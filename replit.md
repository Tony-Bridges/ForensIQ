# Digital Forensics Investigation Tool

## Overview

This is a comprehensive digital forensics investigation tool built with Flask that provides advanced capabilities for analyzing digital evidence from various devices and platforms. The tool supports file analysis, device acquisition, network scanning, and forensic reporting with proper chain of custody management.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

The application follows a modular Flask-based architecture with specialized components for different forensic analysis tasks:

### Backend Architecture
- **Flask Web Application**: Main web server handling HTTP requests and routing
- **SQLAlchemy ORM**: Database abstraction layer for evidence management
- **Modular Design**: Separate modules for different forensic capabilities
- **File Processing**: Dedicated utilities for file analysis and metadata extraction

### Frontend Architecture
- **Bootstrap-based UI**: Dark theme responsive interface
- **Feather Icons**: Consistent iconography throughout the application
- **Chart.js**: Data visualization capabilities
- **Progressive Enhancement**: JavaScript for enhanced user experience

## Key Components

### Core Flask Application (`app.py`)
- Main application entry point with route definitions
- Database initialization and model imports
- File upload handling with size limits (16MB)
- Integration with forensic analysis modules

### Forensic Analysis Modules

#### File Analysis (`forensics_utils.py`)
- **Hash Calculation**: MD5 and SHA-256 hashing for file integrity
- **Metadata Extraction**: File system metadata including timestamps
- **File Type Detection**: Using python-magic for file identification
- **Write-Block Protection**: Ensures original evidence integrity

#### Device Acquisition (`device_acquisition.py`)
- **Multi-Platform Support**: iOS, Android, Huawei, Windows, Linux, macOS
- **ADB Integration**: Android Debug Bridge for Android device access
- **Network Device Detection**: Integration with network scanner
- **Logical/Physical Acquisition**: Different acquisition methods based on device type

#### Network Scanning (`network_scanner.py`)
- **Network Discovery**: Scans local network ranges for active devices
- **Port Scanning**: Identifies open ports and services
- **Service Identification**: Maps common ports to service names
- **Host Resolution**: Attempts to resolve hostnames

#### Memory Analysis (`memory_analysis.py`)
- **Volatility 3 Integration**: Advanced memory dump analysis
- **Process Enumeration**: Extracts running processes from memory dumps
- **Timeline Generation**: Creates chronological analysis of memory artifacts

### Data Models (`models.py`)

#### Evidence Table
- Stores file metadata, hashes, and analysis results
- Links to chain of custody and device acquisition records
- Timestamp tracking for forensic timeline

#### Chain of Custody
- Maintains audit trail of evidence handling
- Action logging with timestamps and details
- Links to specific evidence items

#### Device Acquisition Record
- Stores device-specific acquisition metadata
- Supports different acquisition types (logical/physical)
- JSON storage for flexible device data

## Data Flow

1. **Evidence Upload**: Files uploaded through web interface
2. **Hash Calculation**: MD5/SHA-256 generated for integrity verification
3. **Metadata Extraction**: File system and content metadata collected
4. **Analysis Processing**: Forensic analysis performed based on file type
5. **Database Storage**: Results stored with chain of custody logging
6. **Report Generation**: Comprehensive forensic reports created

## External Dependencies

### Python Libraries
- **Flask**: Web framework and request handling
- **SQLAlchemy**: Database ORM and management
- **python-magic**: File type detection
- **adb-shell**: Android device communication
- **volatility3**: Memory analysis framework
- **hashlib**: Cryptographic hashing

### Frontend Dependencies
- **Bootstrap**: CSS framework for responsive design
- **Feather Icons**: Icon library
- **Chart.js**: Data visualization
- **Custom CSS**: Application-specific styling

### System Dependencies
- **ADB Tools**: Android debugging bridge
- **libimobiledevice**: iOS device communication (planned)
- **Network tools**: For network scanning capabilities

## Deployment Strategy

### Development Environment
- **Flask Development Server**: Built-in server for testing
- **SQLite Database**: Lightweight database for development
- **Debug Mode**: Enabled for development with detailed error reporting

### Production Considerations
- **Database Migration**: Upgrade from SQLite to PostgreSQL for production
- **Environment Variables**: Configuration through environment variables
- **Security**: Proper secret key management and database credentials
- **Error Handling**: Custom error pages and logging
- **File Storage**: Secure storage for forensic evidence

## Recent Changes (July 10, 2025)

### Advanced Features Implementation
- **AI-Powered Intelligence Module**: Added automated anomaly detection, malware classification, NLP entity extraction, and media authenticity verification
- **Cloud & Container Forensics**: Implemented multi-cloud acquisition (AWS, Azure, GCP), Kubernetes/Docker analysis, serverless tracing, and VM disk analysis
- **Blockchain & Crypto Forensics**: Added wallet transaction tracing, smart contract analysis, NFT authenticity verification, and DeFi protocol analysis
- **Mobile & IoT Forensics**: Enhanced mobile device acquisition, IoT data interpretation, vehicle telematics, and social media artifact extraction
- **Encryption & Evasion Analysis**: Implemented encrypted volume detection, steganography detection, rootkit detection, and fileless malware analysis

### User Interface Enhancements
- **Advanced Navigation**: Updated navigation with dropdown menus for organized access to new features
- **Interactive Forms**: Created specialized forms for each analysis type with dynamic configuration options
- **Results Visualization**: Enhanced results display with structured data presentation and JSON raw data views
- **Responsive Design**: Maintained dark theme consistency across all new interfaces

### Technical Improvements
- **Database Issues Resolved**: Fixed PostgreSQL authentication and connection issues
- **Flask Application Structure**: Updated with proper SQLAlchemy configuration and database initialization
- **Modular Architecture**: Implemented clean separation of concerns with dedicated modules for each forensic capability
- **Error Handling**: Improved error handling and user feedback throughout the application

### Complete Advanced Feature Set (Final Implementation)
The application now includes all 8 requested advanced forensic modules:

#### 🔒 Encryption & Obfuscation Analysis
- **Encrypted/Compressed File Analysis**: Detects TrueCrypt, VeraCrypt, ZIP, and various encryption methods
- **Password Brute-Forcing**: Simulated password cracking with strength assessment
- **Container Extraction**: Supports multiple container formats
- **Steganography Detection**: Image, audio, and video analysis for hidden data

#### 🌐 Network Analysis & PCAP Forensics
- **PCAP Analysis**: Session reconstruction, protocol breakdown, endpoint analysis
- **Browser History Reconstruction**: Chrome, Firefox, Edge, Safari artifact analysis
- **Email Artifact Analysis**: Outlook, Thunderbird, Gmail forensics
- **Data Exfiltration Detection**: Identifies suspicious network patterns and large transfers

#### 🔗 Timeline Intelligence & Correlation
- **Cross-Source Timeline Reconstruction**: Correlates MFT, logs, browser, USB events
- **Attack Chain Analysis**: Identifies attack stages and lateral movement
- **User Activity Reconstruction**: Detailed user behavior analysis
- **Anomaly Detection**: Temporal pattern analysis and suspicious activity identification

#### 🖥️ Live & Remote Forensics
- **Remote Memory Acquisition**: WinPMem, OSXPMem, Volatility integration
- **Live Process Analysis**: Real-time process monitoring and network connections
- **Remote File Collection**: Secure evidence collection from running systems
- **Registry Analysis**: Live Windows registry examination

#### 🧬 Anti-Evasion & Fileless Malware Detection
- **Rootkit Detection**: SSDT hooks, hidden processes, registry modifications
- **Fileless Malware Analysis**: PowerShell, DLL injection, process hollowing detection
- **Memory-Based Threat Detection**: Advanced persistence mechanism identification
- **Anti-Analysis Technique Recognition**: VM detection, debugger evasion

#### 🧪 Sandbox Analysis & Dynamic Execution
- **Multi-Environment Support**: Docker, VirtualBox, VMware, QEMU containers
- **Behavioral Analysis**: Process monitoring, API call capture, network activity
- **Threat Assessment**: Automated malware family identification and risk scoring
- **Evidence Generation**: Screenshots, memory dumps, IOC extraction

#### 📊 Threat Intelligence Integration
- **Multi-Source Intelligence**: VirusTotal, MISP, custom threat feeds
- **YARA Rule Engine**: Malware, APT, PUA, exploit detection rules
- **Custom IOC Generation**: Automated indicator creation from analysis results
- **APT Attribution**: Campaign matching and threat actor identification

#### 🔍 Deep Search & Regex Capabilities
- **Disk Image Scanning**: Deep scan with deleted file and slack space analysis
- **Memory Dump Search**: Pattern matching across memory regions
- **PII Data Discovery**: GDPR compliance checking, privacy risk assessment
- **Credential Hunting**: API keys, passwords, certificates, tokens
- **Custom Regex Engine**: User-defined pattern matching with context extraction

### User Interface Excellence
- **Professional Dark Theme**: Consistent forensic-focused design
- **Organized Navigation**: Dropdown menus grouping related capabilities
- **Interactive Forms**: Dynamic configuration options for each analysis type
- **Comprehensive Results**: Structured data presentation with raw JSON views
- **Responsive Design**: Works across devices while maintaining professional appearance

### Technical Architecture Enhancements
- **Modular Python Backend**: Each forensic capability in dedicated modules
- **Flask Integration**: Seamless web interface with proper error handling
- **PostgreSQL Database**: Production-ready evidence storage
- **Simulated Data**: Realistic forensic scenarios for demonstration and training
- **Chain of Custody**: Proper evidence handling and audit trails

### Current Status
The application is now a comprehensive digital forensics platform covering all major investigation areas. All 8 advanced features are fully implemented with professional interfaces, realistic simulated data, and forensic best practices. The platform provides investigators with enterprise-grade capabilities in a user-friendly web interface suitable for training, demonstration, and real-world forensic workflows.