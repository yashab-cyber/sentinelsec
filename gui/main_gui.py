import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkinter
from matplotlib.figure import Figure
import matplotlib.animation as animation
from datetime import datetime, timedelta
import threading
import time
import json
from typing import Dict, List, Any
import logging

class CVEPopup:
    def __init__(self, parent, cve_data: Dict[str, Any]):
        self.parent = parent
        self.cve_data = cve_data
        self.window = None
        self.show_popup()
    
    def show_popup(self):
        """Show CVE alert popup"""
        self.window = tk.Toplevel(self.parent)
        self.window.title("CVE Alert")
        self.window.geometry("600x400")
        self.window.configure(bg='#2b2b2b')
        self.window.transient(self.parent)
        self.window.grab_set()
        
        # Center the window
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() // 2) - (600 // 2)
        y = (self.window.winfo_screenheight() // 2) - (400 // 2)
        self.window.geometry(f"600x400+{x}+{y}")
        
        # Create widgets
        self.create_widgets()
    
    def create_widgets(self):
        """Create popup widgets"""
        # Title
        title_frame = tk.Frame(self.window, bg='#2b2b2b')
        title_frame.pack(fill='x', padx=10, pady=5)
        
        title_label = tk.Label(
            title_frame,
            text="🚨 CVE ALERT",
            font=('Arial', 16, 'bold'),
            fg='#ff4444',
            bg='#2b2b2b'
        )
        title_label.pack()
        
        # CVE ID
        cve_id = self.cve_data.get('cve_id', 'Unknown')
        id_label = tk.Label(
            title_frame,
            text=f"CVE ID: {cve_id}",
            font=('Arial', 12, 'bold'),
            fg='#ffffff',
            bg='#2b2b2b'
        )
        id_label.pack()
        
        # Severity and CVSS Score
        severity = self.cve_data.get('severity', 'Unknown')
        cvss_score = self.cve_data.get('cvss_score', 0)
        
        severity_frame = tk.Frame(self.window, bg='#2b2b2b')
        severity_frame.pack(fill='x', padx=10, pady=5)
        
        severity_colors = {
            'CRITICAL': '#ff0000',
            'HIGH': '#ff6600',
            'MEDIUM': '#ffaa00',
            'LOW': '#00aa00',
            'UNKNOWN': '#666666'
        }
        
        severity_color = severity_colors.get(severity.upper(), '#666666')
        
        tk.Label(
            severity_frame,
            text=f"Severity: {severity.upper()}",
            font=('Arial', 10, 'bold'),
            fg=severity_color,
            bg='#2b2b2b'
        ).pack(side='left')
        
        tk.Label(
            severity_frame,
            text=f"CVSS Score: {cvss_score:.1f}",
            font=('Arial', 10),
            fg='#ffffff',
            bg='#2b2b2b'
        ).pack(side='right')
        
        # Description
        desc_frame = tk.LabelFrame(
            self.window,
            text="Description",
            fg='#ffffff',
            bg='#2b2b2b',
            font=('Arial', 10, 'bold')
        )
        desc_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        desc_text = tk.Text(
            desc_frame,
            wrap='word',
            font=('Arial', 9),
            fg='#ffffff',
            bg='#3b3b3b',
            height=6
        )
        desc_text.pack(fill='both', expand=True, padx=5, pady=5)
        desc_text.insert('1.0', self.cve_data.get('description', 'No description available'))
        desc_text.config(state='disabled')
        
        # Network Details
        network_frame = tk.LabelFrame(
            self.window,
            text="Network Details",
            fg='#ffffff',
            bg='#2b2b2b',
            font=('Arial', 10, 'bold')
        )
        network_frame.pack(fill='x', padx=10, pady=5)
        
        details_frame = tk.Frame(network_frame, bg='#2b2b2b')
        details_frame.pack(fill='x', padx=5, pady=5)
        
        # Source IP
        src_ip = self.cve_data.get('source_ip', 'Unknown')
        tk.Label(
            details_frame,
            text=f"Source IP: {src_ip}",
            font=('Arial', 9),
            fg='#ffffff',
            bg='#2b2b2b'
        ).pack(anchor='w')
        
        # Destination IP
        dst_ip = self.cve_data.get('destination_ip', 'Unknown')
        tk.Label(
            details_frame,
            text=f"Destination IP: {dst_ip}",
            font=('Arial', 9),
            fg='#ffffff',
            bg='#2b2b2b'
        ).pack(anchor='w')
        
        # Software/Service
        software = self.cve_data.get('software', self.cve_data.get('service', 'Unknown'))
        tk.Label(
            details_frame,
            text=f"Software/Service: {software}",
            font=('Arial', 9),
            fg='#ffffff',
            bg='#2b2b2b'
        ).pack(anchor='w')
        
        # Version (if available)
        version = self.cve_data.get('version')
        if version:
            tk.Label(
                details_frame,
                text=f"Version: {version}",
                font=('Arial', 9),
                fg='#ffffff',
                bg='#2b2b2b'
            ).pack(anchor='w')
        
        # Port (if available)
        port = self.cve_data.get('port')
        if port:
            tk.Label(
                details_frame,
                text=f"Port: {port}",
                font=('Arial', 9),
                fg='#ffffff',
                bg='#2b2b2b'
            ).pack(anchor='w')
        
        # Buttons
        button_frame = tk.Frame(self.window, bg='#2b2b2b')
        button_frame.pack(fill='x', padx=10, pady=10)
        
        # Close button
        close_btn = tk.Button(
            button_frame,
            text="Close",
            command=self.close_popup,
            bg='#ff4444',
            fg='white',
            font=('Arial', 10, 'bold'),
            relief='flat',
            padx=20
        )
        close_btn.pack(side='right', padx=5)
        
        # More Info button
        info_btn = tk.Button(
            button_frame,
            text="More Info",
            command=self.show_more_info,
            bg='#4444ff',
            fg='white',
            font=('Arial', 10, 'bold'),
            relief='flat',
            padx=20
        )
        info_btn.pack(side='right', padx=5)
        
        # Acknowledge button
        ack_btn = tk.Button(
            button_frame,
            text="Acknowledge",
            command=self.acknowledge_alert,
            bg='#44aa44',
            fg='white',
            font=('Arial', 10, 'bold'),
            relief='flat',
            padx=20
        )
        ack_btn.pack(side='right', padx=5)
    
    def show_more_info(self):
        """Show more detailed CVE information"""
        info_window = tk.Toplevel(self.window)
        info_window.title(f"CVE Details - {self.cve_data.get('cve_id', 'Unknown')}")
        info_window.geometry("700x500")
        info_window.configure(bg='#2b2b2b')
        
        # Create notebook for tabs
        notebook = ttk.Notebook(info_window)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Configure ttk styles for dark theme
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#2b2b2b')
        style.configure('TNotebook.Tab', background='#3b3b3b', foreground='white')
        
        # Details tab
        details_frame = tk.Frame(notebook, bg='#2b2b2b')
        notebook.add(details_frame, text="Details")
        
        details_text = tk.Text(
            details_frame,
            wrap='word',
            font=('Arial', 9),
            fg='#ffffff',
            bg='#3b3b3b'
        )
        details_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Add detailed information
        details_info = f"""CVE ID: {self.cve_data.get('cve_id', 'Unknown')}
Severity: {self.cve_data.get('severity', 'Unknown')}
CVSS Score: {self.cve_data.get('cvss_score', 0)}

Description:
{self.cve_data.get('description', 'No description available')}

Network Information:
Source IP: {self.cve_data.get('source_ip', 'Unknown')}
Destination IP: {self.cve_data.get('destination_ip', 'Unknown')}
Software/Service: {self.cve_data.get('software', self.cve_data.get('service', 'Unknown'))}
"""
        
        if self.cve_data.get('version'):
            details_info += f"Version: {self.cve_data.get('version')}\n"
        
        if self.cve_data.get('port'):
            details_info += f"Port: {self.cve_data.get('port')}\n"
        
        details_text.insert('1.0', details_info)
        details_text.config(state='disabled')
        
        # References tab (if available)
        references = self.cve_data.get('references', [])
        if references:
            ref_frame = tk.Frame(notebook, bg='#2b2b2b')
            notebook.add(ref_frame, text="References")
            
            ref_text = tk.Text(
                ref_frame,
                wrap='word',
                font=('Arial', 9),
                fg='#ffffff',
                bg='#3b3b3b'
            )
            ref_text.pack(fill='both', expand=True, padx=5, pady=5)
            
            ref_info = "References:\n\n"
            for i, ref in enumerate(references, 1):
                if isinstance(ref, dict):
                    ref_info += f"{i}. {ref.get('url', 'No URL')}\n"
                    if ref.get('source'):
                        ref_info += f"   Source: {ref.get('source')}\n"
                    ref_info += "\n"
                else:
                    ref_info += f"{i}. {ref}\n\n"
            
            ref_text.insert('1.0', ref_info)
            ref_text.config(state='disabled')
    
    def acknowledge_alert(self):
        """Acknowledge the CVE alert"""
        try:
            # Here you could update the alert status in the database
            messagebox.showinfo("Alert Acknowledged", "CVE alert has been acknowledged.")
            self.close_popup()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to acknowledge alert: {e}")
    
    def close_popup(self):
        """Close the popup window"""
        if self.window:
            self.window.destroy()

class SentinelSecGUI:
    def __init__(self, config, mongo_handler, packet_sniffer, rule_engine, anomaly_detector, cve_checker):
        self.config = config
        self.mongo_handler = mongo_handler
        self.packet_sniffer = packet_sniffer
        self.rule_engine = rule_engine
        self.anomaly_detector = anomaly_detector
        self.cve_checker = cve_checker
        
        self.logger = logging.getLogger(__name__)
        
        # GUI state
        self.is_running = False
        self.refresh_interval = config.get('gui', {}).get('refresh_interval', 1000)
        
        # Initialize main window
        self.root = tk.Tk()
        self.root.title("SentinelSec - Intrusion Detection System")
        self.root.geometry("1400x900")
        self.configure_dark_theme()
        
        # Data for charts
        self.chart_data = {
            'timestamps': [],
            'packet_counts': [],
            'protocol_counts': {},
            'alert_counts': []
        }
        
        # Create GUI components
        self.create_menu()
        self.create_widgets()
        self.setup_charts()
        
        # Start data refresh
        self.refresh_data()
        
        # Register packet callback
        self.packet_sniffer.add_callback(self.on_packet_received)
    
    def configure_dark_theme(self):
        """Configure dark theme for the application"""
        self.root.configure(bg='#2b2b2b')
        
        # Configure ttk styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles for dark theme
        style.configure('TFrame', background='#2b2b2b')
        style.configure('TLabel', background='#2b2b2b', foreground='white')
        style.configure('TButton', background='#4b4b4b', foreground='white')
        style.configure('TEntry', background='#3b3b3b', foreground='white')
        style.configure('TText', background='#3b3b3b', foreground='white')
        style.configure('TTreeview', background='#3b3b3b', foreground='white')
        style.configure('TTreeview.Heading', background='#4b4b4b', foreground='white')
        style.configure('TNotebook', background='#2b2b2b')
        style.configure('TNotebook.Tab', background='#3b3b3b', foreground='white')
        
        # Configure matplotlib for dark theme
        plt.style.use('dark_background')
    
    def create_menu(self):
        """Create application menu"""
        menubar = tk.Menu(self.root, bg='#2b2b2b', fg='white')
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg='#2b2b2b', fg='white')
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Logs", command=self.export_logs)
        file_menu.add_command(label="Backup Database", command=self.backup_database)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0, bg='#2b2b2b', fg='white')
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Rule Editor", command=self.open_rule_editor)
        tools_menu.add_command(label="CVE Sync", command=self.sync_cve_data)
        tools_menu.add_command(label="Train AI Model", command=self.train_ai_model)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0, bg='#2b2b2b', fg='white')
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Packet Details", command=self.show_packet_details)
        view_menu.add_command(label="System Statistics", command=self.show_system_stats)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg='#2b2b2b', fg='white')
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def create_widgets(self):
        """Create main GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Top control panel
        self.create_control_panel(main_frame)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill='both', expand=True, pady=5)
        
        # Dashboard tab
        self.create_dashboard_tab()
        
        # Alerts tab
        self.create_alerts_tab()
        
        # Logs tab
        self.create_logs_tab()
        
        # Rules tab
        self.create_rules_tab()
        
        # Statistics tab
        self.create_statistics_tab()
    
    def create_control_panel(self, parent):
        """Create control panel with start/stop buttons and status"""
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill='x', pady=5)
        
        # Left side - controls
        left_frame = ttk.Frame(control_frame)
        left_frame.pack(side='left', fill='x', expand=True)
        
        # Start/Stop button
        self.start_stop_btn = tk.Button(
            left_frame,
            text="Start Monitoring",
            command=self.toggle_monitoring,
            bg='#44aa44',
            fg='white',
            font=('Arial', 12, 'bold'),
            relief='flat',
            padx=20,
            pady=5
        )
        self.start_stop_btn.pack(side='left', padx=5)
        
        # Interface selection
        tk.Label(left_frame, text="Interface:", bg='#2b2b2b', fg='white').pack(side='left', padx=5)
        
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(
            left_frame,
            textvariable=self.interface_var,
            values=self.packet_sniffer.get_available_interfaces(),
            state='readonly',
            width=15
        )
        self.interface_combo.pack(side='left', padx=5)
        self.interface_combo.set('auto')
        
        # AI toggle
        self.ai_var = tk.BooleanVar(value=self.anomaly_detector.enabled)
        ai_check = tk.Checkbutton(
            left_frame,
            text="AI Detection",
            variable=self.ai_var,
            command=self.toggle_ai,
            bg='#2b2b2b',
            fg='white',
            selectcolor='#4b4b4b'
        )
        ai_check.pack(side='left', padx=10)
        
        # Right side - status
        right_frame = ttk.Frame(control_frame)
        right_frame.pack(side='right')
        
        # Status indicators
        self.status_labels = {}
        
        # Packet count
        self.status_labels['packets'] = tk.Label(
            right_frame,
            text="Packets: 0",
            bg='#2b2b2b',
            fg='#44aa44',
            font=('Arial', 10, 'bold')
        )
        self.status_labels['packets'].pack(side='left', padx=10)
        
        # Alert count
        self.status_labels['alerts'] = tk.Label(
            right_frame,
            text="Alerts: 0",
            bg='#2b2b2b',
            fg='#ff4444',
            font=('Arial', 10, 'bold')
        )
        self.status_labels['alerts'].pack(side='left', padx=10)
        
        # Status indicator
        self.status_labels['status'] = tk.Label(
            right_frame,
            text="● STOPPED",
            bg='#2b2b2b',
            fg='#ff4444',
            font=('Arial', 10, 'bold')
        )
        self.status_labels['status'].pack(side='left', padx=10)
    
    def create_dashboard_tab(self):
        """Create dashboard tab with live charts"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")
        
        # Create chart containers
        charts_frame = ttk.Frame(dashboard_frame)
        charts_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Traffic chart (top left)
        self.traffic_frame = ttk.Frame(charts_frame)
        self.traffic_frame.pack(side='left', fill='both', expand=True, padx=2)
        
        # Protocol chart (top right)
        self.protocol_frame = ttk.Frame(charts_frame)
        self.protocol_frame.pack(side='right', fill='both', expand=True, padx=2)
        
        # Alert chart (bottom)
        self.alert_frame = ttk.Frame(dashboard_frame)
        self.alert_frame.pack(fill='both', expand=True, padx=5, pady=5)
    
    def create_alerts_tab(self):
        """Create alerts tab"""
        alerts_frame = ttk.Frame(self.notebook)
        self.notebook.add(alerts_frame, text="Alerts")
        
        # Filter frame
        filter_frame = ttk.Frame(alerts_frame)
        filter_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(filter_frame, text="Filter by Severity:", bg='#2b2b2b', fg='white').pack(side='left', padx=5)
        
        self.severity_filter = ttk.Combobox(
            filter_frame,
            values=['All', 'Critical', 'High', 'Medium', 'Low'],
            state='readonly',
            width=10
        )
        self.severity_filter.pack(side='left', padx=5)
        self.severity_filter.set('All')
        
        filter_btn = tk.Button(
            filter_frame,
            text="Apply Filter",
            command=self.apply_alert_filter,
            bg='#4444ff',
            fg='white',
            relief='flat'
        )
        filter_btn.pack(side='left', padx=5)
        
        # Alerts treeview
        self.alerts_tree = ttk.Treeview(
            alerts_frame,
            columns=('timestamp', 'type', 'severity', 'source', 'description'),
            show='headings',
            height=20
        )
        
        # Configure columns
        self.alerts_tree.heading('timestamp', text='Timestamp')
        self.alerts_tree.heading('type', text='Type')
        self.alerts_tree.heading('severity', text='Severity')
        self.alerts_tree.heading('source', text='Source IP')
        self.alerts_tree.heading('description', text='Description')
        
        self.alerts_tree.column('timestamp', width=150)
        self.alerts_tree.column('type', width=100)
        self.alerts_tree.column('severity', width=80)
        self.alerts_tree.column('source', width=120)
        self.alerts_tree.column('description', width=400)
        
        # Scrollbar for alerts
        alerts_scrollbar = ttk.Scrollbar(alerts_frame, orient='vertical', command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=alerts_scrollbar.set)
        
        self.alerts_tree.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        alerts_scrollbar.pack(side='right', fill='y')
        
        # Bind double-click event
        self.alerts_tree.bind('<Double-1>', self.on_alert_double_click)
    
    def create_logs_tab(self):
        """Create logs tab for packet viewing"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Packet Logs")
        
        # Filter frame
        filter_frame = ttk.Frame(logs_frame)
        filter_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(filter_frame, text="Filter by IP:", bg='#2b2b2b', fg='white').pack(side='left', padx=5)
        
        self.ip_filter = tk.Entry(filter_frame, bg='#3b3b3b', fg='white', width=15)
        self.ip_filter.pack(side='left', padx=5)
        
        tk.Label(filter_frame, text="Protocol:", bg='#2b2b2b', fg='white').pack(side='left', padx=5)
        
        self.protocol_filter = ttk.Combobox(
            filter_frame,
            values=['All', 'TCP', 'UDP', 'ICMP', 'HTTP', 'DNS', 'ARP'],
            state='readonly',
            width=10
        )
        self.protocol_filter.pack(side='left', padx=5)
        self.protocol_filter.set('All')
        
        filter_btn = tk.Button(
            filter_frame,
            text="Apply Filter",
            command=self.apply_packet_filter,
            bg='#4444ff',
            fg='white',
            relief='flat'
        )
        filter_btn.pack(side='left', padx=5)
        
        # Packets treeview
        self.packets_tree = ttk.Treeview(
            logs_frame,
            columns=('timestamp', 'protocol', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'size'),
            show='headings',
            height=25
        )
        
        # Configure columns
        self.packets_tree.heading('timestamp', text='Timestamp')
        self.packets_tree.heading('protocol', text='Protocol')
        self.packets_tree.heading('src_ip', text='Source IP')
        self.packets_tree.heading('dst_ip', text='Dest IP')
        self.packets_tree.heading('src_port', text='Src Port')
        self.packets_tree.heading('dst_port', text='Dst Port')
        self.packets_tree.heading('size', text='Size')
        
        self.packets_tree.column('timestamp', width=150)
        self.packets_tree.column('protocol', width=80)
        self.packets_tree.column('src_ip', width=120)
        self.packets_tree.column('dst_ip', width=120)
        self.packets_tree.column('src_port', width=80)
        self.packets_tree.column('dst_port', width=80)
        self.packets_tree.column('size', width=80)
        
        # Scrollbar for packets
        packets_scrollbar = ttk.Scrollbar(logs_frame, orient='vertical', command=self.packets_tree.yview)
        self.packets_tree.configure(yscrollcommand=packets_scrollbar.set)
        
        self.packets_tree.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        packets_scrollbar.pack(side='right', fill='y')
    
    def create_rules_tab(self):
        """Create rules management tab"""
        rules_frame = ttk.Frame(self.notebook)
        self.notebook.add(rules_frame, text="Rules")
        
        # Rules control frame
        control_frame = ttk.Frame(rules_frame)
        control_frame.pack(fill='x', padx=5, pady=5)
        
        add_btn = tk.Button(
            control_frame,
            text="Add Rule",
            command=self.add_rule,
            bg='#44aa44',
            fg='white',
            relief='flat'
        )
        add_btn.pack(side='left', padx=5)
        
        edit_btn = tk.Button(
            control_frame,
            text="Edit Rule",
            command=self.edit_rule,
            bg='#4444ff',
            fg='white',
            relief='flat'
        )
        edit_btn.pack(side='left', padx=5)
        
        delete_btn = tk.Button(
            control_frame,
            text="Delete Rule",
            command=self.delete_rule,
            bg='#ff4444',
            fg='white',
            relief='flat'
        )
        delete_btn.pack(side='left', padx=5)
        
        # Rules treeview
        self.rules_tree = ttk.Treeview(
            rules_frame,
            columns=('enabled', 'name', 'type', 'severity', 'description'),
            show='headings',
            height=20
        )
        
        # Configure columns
        self.rules_tree.heading('enabled', text='Enabled')
        self.rules_tree.heading('name', text='Name')
        self.rules_tree.heading('type', text='Type')
        self.rules_tree.heading('severity', text='Severity')
        self.rules_tree.heading('description', text='Description')
        
        self.rules_tree.column('enabled', width=80)
        self.rules_tree.column('name', width=200)
        self.rules_tree.column('type', width=100)
        self.rules_tree.column('severity', width=100)
        self.rules_tree.column('description', width=400)
        
        # Scrollbar for rules
        rules_scrollbar = ttk.Scrollbar(rules_frame, orient='vertical', command=self.rules_tree.yview)
        self.rules_tree.configure(yscrollcommand=rules_scrollbar.set)
        
        self.rules_tree.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        rules_scrollbar.pack(side='right', fill='y')
        
        # Load rules
        self.refresh_rules()
    
    def create_statistics_tab(self):
        """Create statistics tab"""
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="Statistics")
        
        # Statistics text widget
        self.stats_text = tk.Text(
            stats_frame,
            wrap='word',
            font=('Courier', 10),
            fg='#ffffff',
            bg='#3b3b3b',
            state='disabled'
        )
        self.stats_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Refresh button
        refresh_btn = tk.Button(
            stats_frame,
            text="Refresh Statistics",
            command=self.refresh_statistics,
            bg='#4444ff',
            fg='white',
            relief='flat'
        )
        refresh_btn.pack(pady=5)
    
    def setup_charts(self):
        """Setup matplotlib charts"""
        # Traffic chart
        self.traffic_fig = Figure(figsize=(6, 4), facecolor='#2b2b2b')
        self.traffic_ax = self.traffic_fig.add_subplot(111, facecolor='#2b2b2b')
        self.traffic_ax.set_title('Traffic Rate (packets/sec)', color='white')
        self.traffic_ax.set_xlabel('Time', color='white')
        self.traffic_ax.set_ylabel('Packets/sec', color='white')
        self.traffic_ax.tick_params(colors='white')
        
        self.traffic_canvas = FigureCanvasTkinter(self.traffic_fig, self.traffic_frame)
        self.traffic_canvas.get_tk_widget().pack(fill='both', expand=True)
        
        # Protocol chart
        self.protocol_fig = Figure(figsize=(6, 4), facecolor='#2b2b2b')
        self.protocol_ax = self.protocol_fig.add_subplot(111, facecolor='#2b2b2b')
        self.protocol_ax.set_title('Protocol Distribution', color='white')
        
        self.protocol_canvas = FigureCanvasTkinter(self.protocol_fig, self.protocol_frame)
        self.protocol_canvas.get_tk_widget().pack(fill='both', expand=True)
        
        # Alert chart
        self.alert_fig = Figure(figsize=(12, 3), facecolor='#2b2b2b')
        self.alert_ax = self.alert_fig.add_subplot(111, facecolor='#2b2b2b')
        self.alert_ax.set_title('Alerts Timeline', color='white')
        self.alert_ax.set_xlabel('Time', color='white')
        self.alert_ax.set_ylabel('Alert Count', color='white')
        self.alert_ax.tick_params(colors='white')
        
        self.alert_canvas = FigureCanvasTkinter(self.alert_fig, self.alert_frame)
        self.alert_canvas.get_tk_widget().pack(fill='both', expand=True)
    
    def toggle_monitoring(self):
        """Toggle packet monitoring on/off"""
        if not self.is_running:
            # Start monitoring
            interface = self.interface_var.get()
            if interface == 'auto':
                interface = None
            
            try:
                self.packet_sniffer.start_sniffing(interface)
                self.is_running = True
                self.start_stop_btn.config(text="Stop Monitoring", bg='#ff4444')
                self.status_labels['status'].config(text="● RUNNING", fg='#44aa44')
                self.logger.info("Packet monitoring started")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start monitoring: {e}")
        else:
            # Stop monitoring
            try:
                self.packet_sniffer.stop_sniffing()
                self.is_running = False
                self.start_stop_btn.config(text="Start Monitoring", bg='#44aa44')
                self.status_labels['status'].config(text="● STOPPED", fg='#ff4444')
                self.logger.info("Packet monitoring stopped")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to stop monitoring: {e}")
    
    def toggle_ai(self):
        """Toggle AI anomaly detection"""
        if self.ai_var.get():
            self.anomaly_detector.enable()
            messagebox.showinfo("AI Enabled", "AI anomaly detection enabled")
        else:
            self.anomaly_detector.disable()
            messagebox.showinfo("AI Disabled", "AI anomaly detection disabled")
    
    def on_packet_received(self, packet_data):
        """Callback for when a packet is received"""
        try:
            # Update GUI in thread-safe manner
            self.root.after_idle(self.update_packet_display, packet_data)
            
            # Check for CVE alerts
            if self.cve_checker:
                cve_alerts = self.cve_checker.check_packet_for_cves(packet_data)
                for cve_alert in cve_alerts:
                    self.root.after_idle(self.show_cve_popup, cve_alert)
        
        except Exception as e:
            self.logger.error(f"Error processing packet in GUI: {e}")
    
    def update_packet_display(self, packet_data):
        """Update packet display in GUI"""
        try:
            # Add to packets tree (limit to last 1000 packets)
            if len(self.packets_tree.get_children()) > 1000:
                # Remove oldest entries
                children = self.packets_tree.get_children()
                for child in children[:100]:
                    self.packets_tree.delete(child)
            
            # Insert new packet
            timestamp = packet_data.get('timestamp', datetime.utcnow())
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            self.packets_tree.insert('', 0, values=(
                timestamp.strftime('%H:%M:%S'),
                packet_data.get('protocol', 'Unknown'),
                packet_data.get('src_ip', ''),
                packet_data.get('dst_ip', ''),
                packet_data.get('src_port', ''),
                packet_data.get('dst_port', ''),
                packet_data.get('size', 0)
            ))
        
        except Exception as e:
            self.logger.error(f"Error updating packet display: {e}")
    
    def show_cve_popup(self, cve_alert):
        """Show CVE alert popup"""
        try:
            CVEPopup(self.root, cve_alert)
        except Exception as e:
            self.logger.error(f"Error showing CVE popup: {e}")
    
    def refresh_data(self):
        """Refresh data and update displays"""
        try:
            # Update status labels
            stats = self.packet_sniffer.get_statistics()
            self.status_labels['packets'].config(text=f"Packets: {stats.get('total_packets', 0)}")
            self.status_labels['alerts'].config(text=f"Alerts: {stats.get('alerts', 0)}")
            
            # Update charts
            self.update_charts()
            
            # Update alerts
            self.refresh_alerts()
            
            # Schedule next refresh
            self.root.after(self.refresh_interval, self.refresh_data)
        
        except Exception as e:
            self.logger.error(f"Error refreshing data: {e}")
            # Continue refreshing even if there's an error
            self.root.after(self.refresh_interval, self.refresh_data)
    
    def update_charts(self):
        """Update all charts with latest data"""
        try:
            # Get current time
            now = datetime.now()
            
            # Update traffic chart
            stats = self.packet_sniffer.get_statistics()
            
            # Add current data point
            self.chart_data['timestamps'].append(now)
            self.chart_data['packet_counts'].append(stats.get('total_packets', 0))
            
            # Keep only last 100 data points
            if len(self.chart_data['timestamps']) > 100:
                self.chart_data['timestamps'] = self.chart_data['timestamps'][-100:]
                self.chart_data['packet_counts'] = self.chart_data['packet_counts'][-100:]
            
            # Update traffic chart
            self.traffic_ax.clear()
            self.traffic_ax.plot(self.chart_data['timestamps'], self.chart_data['packet_counts'], 'g-')
            self.traffic_ax.set_title('Traffic Rate', color='white')
            self.traffic_ax.tick_params(colors='white')
            self.traffic_fig.autofmt_xdate()
            self.traffic_canvas.draw()
            
            # Update protocol chart
            protocols = stats.get('protocols', {})
            if protocols:
                self.protocol_ax.clear()
                self.protocol_ax.pie(protocols.values(), labels=protocols.keys(), autopct='%1.1f%%')
                self.protocol_ax.set_title('Protocol Distribution', color='white')
                self.protocol_canvas.draw()
        
        except Exception as e:
            self.logger.error(f"Error updating charts: {e}")
    
    def refresh_alerts(self):
        """Refresh alerts display"""
        try:
            # Clear existing alerts
            for item in self.alerts_tree.get_children():
                self.alerts_tree.delete(item)
            
            # Get recent alerts
            alerts = self.mongo_handler.get_alerts(limit=100)
            
            for alert in alerts:
                timestamp = alert.get('timestamp', datetime.utcnow())
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                
                self.alerts_tree.insert('', 'end', values=(
                    timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    alert.get('type', 'Unknown'),
                    alert.get('severity', 'Unknown'),
                    alert.get('src_ip', ''),
                    alert.get('description', '')[:100]
                ))
        
        except Exception as e:
            self.logger.error(f"Error refreshing alerts: {e}")
    
    def refresh_rules(self):
        """Refresh rules display"""
        try:
            # Clear existing rules
            for item in self.rules_tree.get_children():
                self.rules_tree.delete(item)
            
            # Get rules
            rules = self.rule_engine.get_rules()
            
            for rule in rules:
                self.rules_tree.insert('', 'end', values=(
                    "✓" if rule.get('enabled', True) else "✗",
                    rule.get('name', 'Unknown'),
                    rule.get('type', 'Unknown'),
                    rule.get('severity', 'Unknown'),
                    rule.get('description', '')
                ))
        
        except Exception as e:
            self.logger.error(f"Error refreshing rules: {e}")
    
    def apply_alert_filter(self):
        """Apply filter to alerts"""
        # Implementation for alert filtering
        pass
    
    def apply_packet_filter(self):
        """Apply filter to packets"""
        # Implementation for packet filtering
        pass
    
    def on_alert_double_click(self, event):
        """Handle double-click on alert"""
        # Implementation for alert details
        pass
    
    def export_logs(self):
        """Export logs to file"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv")]
            )
            
            if filename:
                file_extension = filename.split('.')[-1].lower()
                success = self.mongo_handler.export_data('packets', filename, file_extension)
                
                if success:
                    messagebox.showinfo("Export Complete", f"Logs exported to {filename}")
                else:
                    messagebox.showerror("Export Failed", "Failed to export logs")
        
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting logs: {e}")
    
    def backup_database(self):
        """Backup database"""
        try:
            backup_path = filedialog.askdirectory(title="Select Backup Directory")
            
            if backup_path:
                success = self.mongo_handler.backup_database(backup_path)
                
                if success:
                    messagebox.showinfo("Backup Complete", f"Database backed up to {backup_path}")
                else:
                    messagebox.showerror("Backup Failed", "Failed to backup database")
        
        except Exception as e:
            messagebox.showerror("Backup Error", f"Error backing up database: {e}")
    
    def sync_cve_data(self):
        """Sync CVE data from NVD"""
        try:
            # Run in separate thread to avoid blocking GUI
            def sync_thread():
                count = self.cve_checker.sync_recent_cves(days=7)
                self.root.after_idle(
                    lambda: messagebox.showinfo("CVE Sync Complete", f"Synced {count} CVE records")
                )
            
            threading.Thread(target=sync_thread, daemon=True).start()
            messagebox.showinfo("CVE Sync", "CVE synchronization started...")
        
        except Exception as e:
            messagebox.showerror("CVE Sync Error", f"Error syncing CVE data: {e}")
    
    def train_ai_model(self):
        """Train AI anomaly detection model"""
        try:
            # Run in separate thread
            def train_thread():
                success = self.anomaly_detector.train_model()
                message = "AI model training completed successfully" if success else "AI model training failed"
                self.root.after_idle(lambda: messagebox.showinfo("AI Training", message))
            
            threading.Thread(target=train_thread, daemon=True).start()
            messagebox.showinfo("AI Training", "AI model training started...")
        
        except Exception as e:
            messagebox.showerror("AI Training Error", f"Error training AI model: {e}")
    
    def open_rule_editor(self):
        """Open rule editor window"""
        # Implementation for rule editor
        messagebox.showinfo("Rule Editor", "Rule editor functionality coming soon!")
    
    def add_rule(self):
        """Add new rule"""
        # Implementation for adding rules
        messagebox.showinfo("Add Rule", "Add rule functionality coming soon!")
    
    def edit_rule(self):
        """Edit selected rule"""
        # Implementation for editing rules
        messagebox.showinfo("Edit Rule", "Edit rule functionality coming soon!")
    
    def delete_rule(self):
        """Delete selected rule"""
        # Implementation for deleting rules
        messagebox.showinfo("Delete Rule", "Delete rule functionality coming soon!")
    
    def show_packet_details(self):
        """Show packet details window"""
        # Implementation for packet details
        messagebox.showinfo("Packet Details", "Packet details functionality coming soon!")
    
    def show_system_stats(self):
        """Show system statistics window"""
        # Implementation for system stats
        messagebox.showinfo("System Statistics", "System statistics functionality coming soon!")
    
    def refresh_statistics(self):
        """Refresh statistics display"""
        try:
            self.stats_text.config(state='normal')
            self.stats_text.delete('1.0', tk.END)
            
            # Get various statistics
            packet_stats = self.packet_sniffer.get_statistics()
            rule_stats = self.rule_engine.get_rule_statistics()
            anomaly_stats = self.anomaly_detector.get_anomaly_statistics()
            cve_stats = self.cve_checker.get_cve_statistics()
            
            stats_text = f"""
SentinelSec Statistics
====================

Packet Statistics:
- Total Packets: {packet_stats.get('total_packets', 0)}
- Protocols: {', '.join(f"{k}: {v}" for k, v in packet_stats.get('protocols', {}).items())}
- Total Alerts: {packet_stats.get('alerts', 0)}
- Total Anomalies: {packet_stats.get('anomalies', 0)}

Rule Engine Statistics:
- Total Rules: {len(self.rule_engine.get_rules())}
- Active Rules: {sum(1 for r in self.rule_engine.get_rules() if r.get('enabled', True))}

AI Model Information:
- Model Type: {self.anomaly_detector.model_type}
- Model Trained: {self.anomaly_detector.is_trained()}
- AI Enabled: {self.anomaly_detector.enabled}

CVE Database:
- Total CVEs: {cve_stats.get('total_cves', 0)}
- Cache Size: {cve_stats.get('cache_size_mb', 0):.2f} MB

System Status:
- Monitoring: {"Running" if self.is_running else "Stopped"}
- Database: Connected
- Interface: {self.interface_var.get()}
            """
            
            self.stats_text.insert('1.0', stats_text)
            self.stats_text.config(state='disabled')
        
        except Exception as e:
            self.logger.error(f"Error refreshing statistics: {e}")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
SentinelSec v1.0
Intrusion Detection System

Features:
• Real-time packet monitoring
• AI-based anomaly detection
• CVE vulnerability checking
• Rule-based threat detection
• MongoDB data storage
• Offline-first design

Developed with Python, Scapy, MongoDB, and Tkinter
        """
        messagebox.showinfo("About SentinelSec", about_text)
    
    def on_closing(self):
        """Handle application closing"""
        if self.is_running:
            self.packet_sniffer.stop_sniffing()
        
        self.mongo_handler.close()
        self.root.destroy()
    
    def run(self):
        """Start the GUI application"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
