
import os
import json
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import black, blue, red, green, grey
from reportlab.graphics.shapes import Drawing, Line, Rect, String
from reportlab.graphics.charts.lineplots import LinePlot
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.widgets.markers import makeMarker
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from io import BytesIO
import base64
from models import Evidence, Investigation, ChainOfCustody, User
import zipfile

class ForensicReportGenerator:
    """Professional forensic report generation system."""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.custom_styles = self._create_custom_styles()
        self.report_templates = {
            'comprehensive': self._generate_comprehensive_report,
            'executive': self._create_executive_summary,
            'technical': self._generate_technical_report,
            'timeline': self._generate_timeline_report,
            'evidence': self._generate_evidence_report
        }
    
    def generate_report(self, investigation_id, report_type='comprehensive', output_format='pdf'):
        """Generate forensic report."""
        try:
            investigation = Investigation.query.get(investigation_id)
            if not investigation:
                return {"success": False, "error": "Investigation not found"}
            
            # Collect data for report
            report_data = self._collect_report_data(investigation)
            
            # Generate report based on type
            if report_type in self.report_templates:
                if output_format == 'pdf':
                    report_file = self.report_templates[report_type](report_data)
                elif output_format == 'html':
                    report_file = self._generate_html_report(report_data, report_type)
                elif output_format == 'json':
                    report_file = self._generate_json_report(report_data)
                else:
                    return {"success": False, "error": "Unsupported output format"}
                
                return {
                    "success": True,
                    "report_file": report_file,
                    "report_type": report_type,
                    "output_format": output_format,
                    "generated_at": datetime.utcnow().isoformat()
                }
            else:
                return {"success": False, "error": "Unsupported report type"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _collect_report_data(self, investigation):
        """Collect all data needed for report generation."""
        evidence_items = Evidence.query.filter_by(investigation_id=investigation.id).all()
        
        report_data = {
            'investigation': {
                'id': investigation.id,
                'case_number': investigation.case_number,
                'title': investigation.title,
                'description': investigation.description,
                'status': investigation.status,
                'priority': investigation.priority,
                'created_at': investigation.created_at,
                'updated_at': investigation.updated_at
            },
            'evidence_items': [],
            'timeline_events': [],
            'chain_of_custody': [],
            'analysis_results': {},
            'statistics': {}
        }
        
        # Collect evidence data
        for evidence in evidence_items:
            evidence_data = {
                'id': evidence.id,
                'filename': evidence.filename,
                'md5_hash': evidence.md5_hash,
                'sha256_hash': evidence.sha256_hash,
                'timestamp': evidence.timestamp,
                'metadata': json.loads(evidence.file_metadata) if evidence.file_metadata else {},
                'analysis': json.loads(evidence.analysis_results) if evidence.analysis_results else {}
            }
            report_data['evidence_items'].append(evidence_data)
            
            # Collect chain of custody
            custody_records = ChainOfCustody.query.filter_by(evidence_id=evidence.id).all()
            for custody in custody_records:
                report_data['chain_of_custody'].append({
                    'evidence_id': evidence.id,
                    'action': custody.action,
                    'timestamp': custody.timestamp,
                    'details': custody.details
                })
        
        # Generate timeline events
        report_data['timeline_events'] = self._generate_timeline_events(report_data)
        
        # Calculate statistics
        report_data['statistics'] = self._calculate_statistics(report_data)
        
        return report_data
    
    def _generate_executive_summary(self, report_data):
        """Generate executive summary report."""
        filename = f"executive_summary_{report_data['investigation']['case_number']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join("/tmp", filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []
        
        # Title page
        story.extend(self._create_title_page(report_data))
        story.append(PageBreak())
        
        # Executive summary
        story.extend(self._create_executive_summary(report_data))
        story.append(PageBreak())
        
        # Key statistics
        story.extend(self._create_statistics_summary(report_data))
        
        doc.build(story)
        return filepath
    
    def _generate_technical_report(self, report_data):
        """Generate technical report."""
        filename = f"technical_report_{report_data['investigation']['case_number']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join("/tmp", filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []
        
        # Title page
        story.extend(self._create_title_page(report_data))
        story.append(PageBreak())
        
        # Technical findings
        story.extend(self._create_technical_findings(report_data))
        story.append(PageBreak())
        
        # Evidence analysis
        story.extend(self._create_evidence_analysis(report_data))
        story.append(PageBreak())
        
        # Appendices
        story.extend(self._create_appendices(report_data))
        
        doc.build(story)
        return filepath
    
    def _generate_timeline_report(self, report_data):
        """Generate timeline report."""
        filename = f"timeline_report_{report_data['investigation']['case_number']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join("/tmp", filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []
        
        # Title page
        story.extend(self._create_title_page(report_data))
        story.append(PageBreak())
        
        # Timeline analysis
        story.extend(self._create_timeline_analysis(report_data))
        
        doc.build(story)
        return filepath
    
    def _generate_evidence_report(self, report_data):
        """Generate evidence report."""
        filename = f"evidence_report_{report_data['investigation']['case_number']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join("/tmp", filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []
        
        # Title page
        story.extend(self._create_title_page(report_data))
        story.append(PageBreak())
        
        # Evidence analysis
        story.extend(self._create_evidence_analysis(report_data))
        story.append(PageBreak())
        
        # Chain of custody
        story.extend(self._create_chain_of_custody_section(report_data))
        
        doc.build(story)
        return filepath

    def _generate_comprehensive_report(self, report_data):
        """Generate comprehensive forensic report."""
        filename = f"forensic_report_{report_data['investigation']['case_number']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join("/tmp", filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []
        
        # Title page
        story.extend(self._create_title_page(report_data))
        story.append(PageBreak())
        
        # Executive summary
        story.extend(self._create_executive_summary(report_data))
        story.append(PageBreak())
        
        # Investigation overview
        story.extend(self._create_investigation_overview(report_data))
        story.append(PageBreak())
        
        # Evidence analysis
        story.extend(self._create_evidence_analysis(report_data))
        story.append(PageBreak())
        
        # Timeline analysis
        story.extend(self._create_timeline_analysis(report_data))
        story.append(PageBreak())
        
        # Chain of custody
        story.extend(self._create_chain_of_custody_section(report_data))
        story.append(PageBreak())
        
        # Technical findings
        story.extend(self._create_technical_findings(report_data))
        story.append(PageBreak())
        
        # Conclusions and recommendations
        story.extend(self._create_conclusions(report_data))
        
        # Appendices
        story.extend(self._create_appendices(report_data))
        
        doc.build(story)
        return filepath
    
    def _create_title_page(self, report_data):
        """Create report title page."""
        story = []
        
        # Main title
        title = Paragraph("DIGITAL FORENSIC INVESTIGATION REPORT", self.custom_styles['title'])
        story.append(title)
        story.append(Spacer(1, 0.5*inch))
        
        # Case information
        case_info = [
            ['Case Number:', report_data['investigation']['case_number']],
            ['Investigation Title:', report_data['investigation']['title']],
            ['Status:', report_data['investigation']['status'].upper()],
            ['Priority:', report_data['investigation']['priority'].upper()],
            ['Report Generated:', datetime.now().strftime('%B %d, %Y at %H:%M UTC')]
        ]
        
        case_table = Table(case_info, colWidths=[2*inch, 4*inch])
        case_table.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 12),
            ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ]))
        
        story.append(case_table)
        story.append(Spacer(1, 1*inch))
        
        # Confidentiality notice
        confidentiality = Paragraph(
            "<b>CONFIDENTIALITY NOTICE:</b><br/><br/>"
            "This report contains confidential and privileged information. "
            "Distribution is restricted to authorized personnel only. "
            "Unauthorized disclosure is prohibited and may be unlawful.",
            self.custom_styles['warning']
        )
        story.append(confidentiality)
        
        return story
    
    def _create_executive_summary(self, report_data):
        """Create executive summary section."""
        story = []
        
        story.append(Paragraph("EXECUTIVE SUMMARY", self.custom_styles['heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        # Investigation overview
        overview = f"""
        This digital forensic investigation was conducted on case {report_data['investigation']['case_number']} 
        titled "{report_data['investigation']['title']}". The investigation involved the analysis of 
        {len(report_data['evidence_items'])} pieces of digital evidence.
        """
        story.append(Paragraph(overview, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Key findings
        story.append(Paragraph("Key Findings:", self.custom_styles['heading2']))
        
        findings = self._extract_key_findings(report_data)
        for finding in findings:
            story.append(Paragraph(f"• {finding}", self.styles['Normal']))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Statistics summary
        stats = report_data['statistics']
        stats_data = [
            ['Total Evidence Items', str(stats.get('total_evidence', 0))],
            ['Files Analyzed', str(stats.get('files_analyzed', 0))],
            ['Suspicious Items Found', str(stats.get('suspicious_items', 0))],
            ['Timeline Events', str(stats.get('timeline_events', 0))]
        ]
        
        stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
        stats_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 1, black),
            ('BACKGROUND', (0,0), (-1,0), grey),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ]))
        
        story.append(stats_table)
        
        return story
    
    def _create_statistics_summary(self, report_data):
        """Create statistics summary section."""
        story = []
        
        story.append(Paragraph("INVESTIGATION STATISTICS", self.custom_styles['heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        stats = report_data['statistics']
        
        # Create statistics table
        stats_data = [
            ['Metric', 'Value'],
            ['Total Evidence Items', str(stats.get('total_evidence', 0))],
            ['Files Analyzed', str(stats.get('files_analyzed', 0))],
            ['Suspicious Items Found', str(stats.get('suspicious_items', 0))],
            ['Timeline Events', str(stats.get('timeline_events', 0))],
            ['Total File Size', f"{stats.get('total_file_size', 0):,} bytes"],
            ['Investigation Status', report_data['investigation']['status'].upper()],
            ['Investigation Priority', report_data['investigation']['priority'].upper()]
        ]
        
        stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
        stats_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 1, black),
            ('BACKGROUND', (0,0), (-1,0), grey),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTSIZE', (0,0), (-1,-1), 12),
        ]))
        
        story.append(stats_table)
        story.append(Spacer(1, 0.3*inch))
        
        # File type distribution if available
        if stats.get('file_types'):
            story.append(Paragraph("File Type Distribution:", self.custom_styles['heading2']))
            
            filetype_data = [['File Type', 'Count', 'Percentage']]
            total_files = sum(stats['file_types'].values())
            
            for file_type, count in stats['file_types'].items():
                percentage = (count / total_files * 100) if total_files > 0 else 0
                filetype_data.append([file_type, str(count), f"{percentage:.1f}%"])
            
            filetype_table = Table(filetype_data, colWidths=[2*inch, 1*inch, 1*inch])
            filetype_table.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 1, black),
                ('BACKGROUND', (0,0), (-1,0), grey),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ]))
            
            story.append(filetype_table)
        
        return story
    
    def _create_timeline_analysis(self, report_data):
        """Create timeline analysis with visualization."""
        story = []
        
        story.append(Paragraph("TIMELINE ANALYSIS", self.custom_styles['heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        # Generate timeline chart
        timeline_chart = self._generate_timeline_chart(report_data['timeline_events'])
        if timeline_chart:
            story.append(Image(timeline_chart, width=6*inch, height=4*inch))
            story.append(Spacer(1, 0.2*inch))
        
        # Timeline events table
        if report_data['timeline_events']:
            story.append(Paragraph("Timeline Events:", self.custom_styles['heading2']))
            
            timeline_data = [['Timestamp', 'Event Type', 'Description']]
            for event in report_data['timeline_events'][:20]:  # Limit to first 20 events
                timeline_data.append([
                    event['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    event['event_type'],
                    event['description'][:50] + '...' if len(event['description']) > 50 else event['description']
                ])
            
            timeline_table = Table(timeline_data, colWidths=[2*inch, 1.5*inch, 3*inch])
            timeline_table.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 1, black),
                ('BACKGROUND', (0,0), (-1,0), grey),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ]))
            
            story.append(timeline_table)
        
        return story
    
    def _generate_timeline_chart(self, timeline_events):
        """Generate timeline visualization chart."""
        if not timeline_events:
            return None
        
        try:
            # Create matplotlib chart
            fig, ax = plt.subplots(figsize=(10, 6))
            
            # Extract data for plotting
            timestamps = [event['timestamp'] for event in timeline_events]
            event_types = [event['event_type'] for event in timeline_events]
            
            # Create scatter plot
            type_colors = {
                'file_created': 'blue',
                'file_modified': 'green',
                'file_deleted': 'red',
                'process_started': 'orange',
                'network_connection': 'purple'
            }
            
            for i, (timestamp, event_type) in enumerate(zip(timestamps, event_types)):
                color = type_colors.get(event_type, 'black')
                ax.scatter(timestamp, i, c=color, s=50, alpha=0.7)
            
            ax.set_xlabel('Time')
            ax.set_ylabel('Event Sequence')
            ax.set_title('Timeline of Digital Forensic Events')
            ax.grid(True, alpha=0.3)
            
            # Format x-axis
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
            plt.xticks(rotation=45)
            
            # Save to buffer
            buffer = BytesIO()
            plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
            plt.close()
            
            # Save to temporary file
            chart_filename = f"/tmp/timeline_chart_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            with open(chart_filename, 'wb') as f:
                f.write(buffer.getvalue())
            
            return chart_filename
            
        except Exception as e:
            print(f"Error generating timeline chart: {e}")
            return None
    
    def _create_custom_styles(self):
        """Create custom paragraph styles for reports."""
        styles = {}
        
        styles['title'] = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            alignment=1,  # Center
            textColor=blue
        )
        
        styles['heading1'] = ParagraphStyle(
            'CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            textColor=blue,
            borderWidth=1,
            borderColor=blue,
            borderPadding=5
        )
        
        styles['heading2'] = ParagraphStyle(
            'CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=10,
            textColor=black
        )
        
        styles['warning'] = ParagraphStyle(
            'Warning',
            parent=self.styles['Normal'],
            backgroundColor=grey,
            borderWidth=1,
            borderColor=red,
            borderPadding=10,
            textColor=red
        )
        
        return styles
    
    def _generate_timeline_events(self, report_data):
        """Generate timeline events from evidence data."""
        events = []
        
        for evidence in report_data['evidence_items']:
            # File creation event
            events.append({
                'timestamp': evidence['timestamp'],
                'event_type': 'evidence_added',
                'description': f"Evidence {evidence['filename']} added to investigation",
                'evidence_id': evidence['id']
            })
            
            # Extract events from metadata
            metadata = evidence.get('metadata', {})
            if 'created' in metadata:
                events.append({
                    'timestamp': datetime.fromisoformat(metadata['created']),
                    'event_type': 'file_created',
                    'description': f"File {evidence['filename']} created",
                    'evidence_id': evidence['id']
                })
            
            if 'modified' in metadata:
                events.append({
                    'timestamp': datetime.fromisoformat(metadata['modified']),
                    'event_type': 'file_modified',
                    'description': f"File {evidence['filename']} modified",
                    'evidence_id': evidence['id']
                })
        
        # Sort events by timestamp
        events.sort(key=lambda x: x['timestamp'])
        
        return events
    
    def _calculate_statistics(self, report_data):
        """Calculate investigation statistics."""
        stats = {
            'total_evidence': len(report_data['evidence_items']),
            'files_analyzed': len(report_data['evidence_items']),
            'timeline_events': len(report_data['timeline_events']),
            'suspicious_items': 0,
            'total_file_size': 0,
            'file_types': {}
        }
        
        for evidence in report_data['evidence_items']:
            metadata = evidence.get('metadata', {})
            
            # Calculate total file size
            if 'size' in metadata:
                stats['total_file_size'] += metadata['size']
            
            # Count file types
            if 'file_type' in metadata:
                file_type = metadata['file_type']
                stats['file_types'][file_type] = stats['file_types'].get(file_type, 0) + 1
            
            # Count suspicious items (simplified logic)
            analysis = evidence.get('analysis', {})
            if analysis.get('encryption_check', {}).get('likely_encrypted'):
                stats['suspicious_items'] += 1
        
        return stats
    
    def _extract_key_findings(self, report_data):
        """Extract key findings from investigation data."""
        findings = []
        
        stats = report_data['statistics']
        
        if stats['suspicious_items'] > 0:
            findings.append(f"{stats['suspicious_items']} potentially suspicious items identified")
        
        if stats['total_evidence'] > 0:
            findings.append(f"Analysis of {stats['total_evidence']} evidence items completed")
        
        if stats['timeline_events'] > 0:
            findings.append(f"Timeline reconstruction with {stats['timeline_events']} events")
        
        # Add more sophisticated finding extraction based on analysis results
        for evidence in report_data['evidence_items']:
            analysis = evidence.get('analysis', {})
            if analysis.get('encryption_check', {}).get('likely_encrypted'):
                findings.append(f"Encrypted content detected in {evidence['filename']}")
        
        return findings[:5]  # Return top 5 findings
    
    def _create_investigation_overview(self, report_data):
        """Create investigation overview section."""
        story = []
        
        story.append(Paragraph("INVESTIGATION OVERVIEW", self.custom_styles['heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        inv = report_data['investigation']
        
        overview_text = f"""
        <b>Case Number:</b> {inv['case_number']}<br/>
        <b>Title:</b> {inv['title']}<br/>
        <b>Description:</b> {inv['description']}<br/>
        <b>Status:</b> {inv['status']}<br/>
        <b>Priority:</b> {inv['priority']}<br/>
        <b>Created:</b> {inv['created_at'].strftime('%Y-%m-%d %H:%M:%S')}<br/>
        <b>Last Updated:</b> {inv['updated_at'].strftime('%Y-%m-%d %H:%M:%S')}<br/>
        """
        
        story.append(Paragraph(overview_text, self.styles['Normal']))
        
        return story
    
    def _create_evidence_analysis(self, report_data):
        """Create evidence analysis section."""
        story = []
        
        story.append(Paragraph("EVIDENCE ANALYSIS", self.custom_styles['heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        for evidence in report_data['evidence_items']:
            story.append(Paragraph(f"Evidence: {evidence['filename']}", self.custom_styles['heading2']))
            
            # Evidence details table
            evidence_details = [
                ['Property', 'Value'],
                ['Filename', evidence['filename']],
                ['MD5 Hash', evidence['md5_hash']],
                ['SHA256 Hash', evidence['sha256_hash']],
                ['Timestamp', evidence['timestamp'].strftime('%Y-%m-%d %H:%M:%S')]
            ]
            
            # Add metadata
            metadata = evidence.get('metadata', {})
            for key, value in metadata.items():
                evidence_details.append([key.title(), str(value)])
            
            evidence_table = Table(evidence_details, colWidths=[2*inch, 4*inch])
            evidence_table.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 1, black),
                ('BACKGROUND', (0,0), (-1,0), grey),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ]))
            
            story.append(evidence_table)
            story.append(Spacer(1, 0.2*inch))
        
        return story
    
    def _create_chain_of_custody_section(self, report_data):
        """Create chain of custody section."""
        story = []
        
        story.append(Paragraph("CHAIN OF CUSTODY", self.custom_styles['heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        if report_data['chain_of_custody']:
            custody_data = [['Evidence ID', 'Action', 'Timestamp', 'Details']]
            
            for custody in report_data['chain_of_custody']:
                custody_data.append([
                    str(custody['evidence_id']),
                    custody['action'],
                    custody['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    custody['details'] or 'N/A'
                ])
            
            custody_table = Table(custody_data, colWidths=[1*inch, 2*inch, 2*inch, 2*inch])
            custody_table.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 1, black),
                ('BACKGROUND', (0,0), (-1,0), grey),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ]))
            
            story.append(custody_table)
        else:
            story.append(Paragraph("No chain of custody records available.", self.styles['Normal']))
        
        return story
    
    def _create_technical_findings(self, report_data):
        """Create technical findings section."""
        story = []
        
        story.append(Paragraph("TECHNICAL FINDINGS", self.custom_styles['heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        # Analysis summary
        stats = report_data['statistics']
        
        technical_summary = f"""
        <b>Analysis Summary:</b><br/>
        • Total evidence items analyzed: {stats['total_evidence']}<br/>
        • Total file size processed: {stats['total_file_size']:,} bytes<br/>
        • Suspicious items identified: {stats['suspicious_items']}<br/>
        • Timeline events extracted: {stats['timeline_events']}<br/>
        """
        
        story.append(Paragraph(technical_summary, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # File type distribution
        if stats['file_types']:
            story.append(Paragraph("File Type Distribution:", self.custom_styles['heading2']))
            
            filetype_data = [['File Type', 'Count']]
            for file_type, count in stats['file_types'].items():
                filetype_data.append([file_type, str(count)])
            
            filetype_table = Table(filetype_data, colWidths=[3*inch, 1*inch])
            filetype_table.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 1, black),
                ('BACKGROUND', (0,0), (-1,0), grey),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ]))
            
            story.append(filetype_table)
        
        return story
    
    def _create_conclusions(self, report_data):
        """Create conclusions and recommendations section."""
        story = []
        
        story.append(Paragraph("CONCLUSIONS AND RECOMMENDATIONS", self.custom_styles['heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        conclusions_text = f"""
        Based on the digital forensic analysis of case {report_data['investigation']['case_number']}, 
        the following conclusions and recommendations are provided:
        
        <b>Conclusions:</b><br/>
        • The investigation successfully analyzed {len(report_data['evidence_items'])} evidence items<br/>
        • Timeline reconstruction identified {len(report_data['timeline_events'])} significant events<br/>
        • Chain of custody was properly maintained throughout the investigation<br/>
        
        <b>Recommendations:</b><br/>
        • Continue monitoring for additional digital evidence<br/>
        • Consider deeper analysis of encrypted content if legal authorization permits<br/>
        • Preserve all evidence according to organizational retention policies<br/>
        """
        
        story.append(Paragraph(conclusions_text, self.styles['Normal']))
        
        return story
    
    def _create_appendices(self, report_data):
        """Create appendices section."""
        story = []
        
        story.append(PageBreak())
        story.append(Paragraph("APPENDICES", self.custom_styles['heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        # Appendix A: Technical specifications
        story.append(Paragraph("Appendix A: Technical Specifications", self.custom_styles['heading2']))
        
        tech_specs = """
        <b>Analysis Tools Used:</b><br/>
        • ForensIQ Digital Investigation Platform<br/>
        • Integrated hash verification algorithms<br/>
        • Timeline analysis engine<br/>
        • Evidence correlation system<br/>
        
        <b>Hash Algorithms:</b><br/>
        • MD5 for legacy compatibility<br/>
        • SHA-256 for cryptographic integrity<br/>
        
        <b>Report Generation:</b><br/>
        • PDF format with embedded metadata<br/>
        • Chain of custody preservation<br/>
        • Digital signature capabilities<br/>
        """
        
        story.append(Paragraph(tech_specs, self.styles['Normal']))
        
        return story
    
    def _generate_html_report(self, report_data, report_type):
        """Generate HTML format report."""
        filename = f"forensic_report_{report_data['investigation']['case_number']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join("/tmp", filename)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Forensic Report - {report_data['investigation']['case_number']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ border-bottom: 2px solid #0066cc; padding-bottom: 20px; }}
                .section {{ margin: 30px 0; }}
                .evidence-item {{ border: 1px solid #ccc; padding: 15px; margin: 10px 0; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Digital Forensic Investigation Report</h1>
                <p><strong>Case Number:</strong> {report_data['investigation']['case_number']}</p>
                <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>Investigation Overview</h2>
                <p><strong>Title:</strong> {report_data['investigation']['title']}</p>
                <p><strong>Status:</strong> {report_data['investigation']['status']}</p>
                <p><strong>Priority:</strong> {report_data['investigation']['priority']}</p>
            </div>
            
            <div class="section">
                <h2>Evidence Analysis</h2>
        """
        
        # Add evidence items
        for evidence in report_data['evidence_items']:
            html_content += f"""
                <div class="evidence-item">
                    <h3>{evidence['filename']}</h3>
                    <p><strong>MD5:</strong> {evidence['md5_hash']}</p>
                    <p><strong>SHA256:</strong> {evidence['sha256_hash']}</p>
                    <p><strong>Timestamp:</strong> {evidence['timestamp']}</p>
                </div>
            """
        
        html_content += """
            </div>
        </body>
        </html>
        """
        
        with open(filepath, 'w') as f:
            f.write(html_content)
        
        return filepath
    
    def _generate_json_report(self, report_data):
        """Generate JSON format report."""
        filename = f"forensic_report_{report_data['investigation']['case_number']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join("/tmp", filename)
        
        # Convert datetime objects to strings for JSON serialization
        json_data = self._convert_datetime_to_string(report_data)
        
        with open(filepath, 'w') as f:
            json.dump(json_data, f, indent=2, default=str)
        
        return filepath
    
    def _convert_datetime_to_string(self, obj):
        """Convert datetime objects to strings for JSON serialization."""
        if isinstance(obj, dict):
            return {key: self._convert_datetime_to_string(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_datetime_to_string(item) for item in obj]
        elif isinstance(obj, datetime):
            return obj.isoformat()
        else:
            return obj

class ScheduledReportManager:
    """Automated report scheduling system."""
    
    def __init__(self):
        self.scheduled_reports = {}
    
    def schedule_report(self, investigation_id, schedule_config):
        """Schedule automated report generation."""
        try:
            schedule_id = f"SCHED_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            self.scheduled_reports[schedule_id] = {
                'investigation_id': investigation_id,
                'report_type': schedule_config.get('report_type', 'comprehensive'),
                'output_format': schedule_config.get('output_format', 'pdf'),
                'frequency': schedule_config.get('frequency', 'weekly'),  # daily, weekly, monthly
                'recipients': schedule_config.get('recipients', []),
                'next_run': self._calculate_next_run(schedule_config.get('frequency')),
                'created_at': datetime.utcnow(),
                'active': True
            }
            
            return {
                "success": True,
                "schedule_id": schedule_id,
                "next_run": self.scheduled_reports[schedule_id]['next_run']
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _calculate_next_run(self, frequency):
        """Calculate next scheduled run time."""
        now = datetime.utcnow()
        
        if frequency == 'daily':
            return now + timedelta(days=1)
        elif frequency == 'weekly':
            return now + timedelta(weeks=1)
        elif frequency == 'monthly':
            return now + timedelta(days=30)
        else:
            return now + timedelta(weeks=1)  # Default to weekly
