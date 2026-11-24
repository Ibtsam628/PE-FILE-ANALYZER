r"""
PE File Static Analyzer - Windows Desktop Application
Complete malware analysis tool with modern GUI
Location: D:\PE_Analyzer\pe_analyzer_app.py
"""


import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import customtkinter as ctk
import pefile
import hashlib
import os
import re
import json
import threading
from fpdf import FPDF
from datetime import datetime
from pathlib import Path

# Set appearance mode
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class PEAnalyzerApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("PE Static Analyzer - Malware Analysis Tool")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)
        
        # Set icon (optional - if you have icon.ico)
        try:
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons", "icon.ico")
            self.root.iconbitmap(icon_path)
        except:
            pass
        
        # Variables
        self.current_file = None
        self.pe = None
        self.analysis_results = None
        
        # Setup UI
        self.setup_ui()
        
        # Bind drag and drop
        self.setup_drag_drop()
        
    def setup_ui(self):
        """Create the main UI"""
        
        # Main container
        self.main_container = ctk.CTkFrame(self.root)
        self.main_container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        self.create_header()
        
        # File upload area
        self.create_upload_area()
        
        # Analysis results area (tabs)
        self.create_results_tabs()
        
        # Status bar
        self.create_status_bar()
        
    def create_header(self):
        """Create application header"""
        header_frame = ctk.CTkFrame(self.main_container, height=80)
        header_frame.pack(fill="x", pady=(0, 20))
        header_frame.pack_propagate(False)
        
        # Title
        title = ctk.CTkLabel(
            header_frame, 
            text="🔍 PE File Static Analyzer", 
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="#00d4ff"
        )
        title.pack(pady=10)
        
        # Subtitle
        subtitle = ctk.CTkLabel(
            header_frame,
            text="Advanced Malware Analysis Tool | Static Detection System",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        subtitle.pack()
        
    def create_upload_area(self):
        """Create file upload section"""
        upload_frame = ctk.CTkFrame(self.main_container)
        upload_frame.pack(fill="x", pady=(0, 20))
        
        # Drag and drop area
        self.drop_area = ctk.CTkFrame(
            upload_frame, 
            height=150,
            fg_color="#2b2b2b",
            corner_radius=15
        )
        self.drop_area.pack(fill="x", pady=10)
        self.drop_area.pack_propagate(False)
        
        # Drop area content
        drop_label = ctk.CTkLabel(
            self.drop_area,
            text="📁 Drag & Drop PE File Here\n\nor\n\nClick to Browse",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        drop_label.pack(expand=True)
        
        # Bind click event
        self.drop_area.bind("<Button-1>", lambda e: self.browse_file())
        
        # Buttons frame
        button_frame = ctk.CTkFrame(upload_frame, fg_color="transparent")
        button_frame.pack(pady=10)
        
        self.browse_btn = ctk.CTkButton(
            button_frame,
            text="📂 Browse for PE File",
            command=self.browse_file,
            width=200,
            height=40,
            font=ctk.CTkFont(size=14)
        )
        self.browse_btn.pack(side="left", padx=10)
        
        self.analyze_btn = ctk.CTkButton(
            button_frame,
            text="🚀 Start Analysis",
            command=self.start_analysis,
            width=200,
            height=40,
            font=ctk.CTkFont(size=14),
            state="disabled",
            fg_color="#28a745",
            hover_color="#218838"
        )
        self.analyze_btn.pack(side="left", padx=10)
        
        self.reset_btn = ctk.CTkButton(
            button_frame,
            text="🔄 Reset",
            command=self.reset_app,
            width=150,
            height=40,
            font=ctk.CTkFont(size=14),
            fg_color="#6c757d",
            hover_color="#5a6268"
        )
        self.reset_btn.pack(side="left", padx=10)
        
        # Progress bar
        self.progress = ctk.CTkProgressBar(
            button_frame,
            width=300,
            height=10
        )
        self.progress.pack(side="left", padx=20)
        self.progress.set(0)
        
        # File info label
        self.file_info_label = ctk.CTkLabel(
            upload_frame,
            text="No file selected",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.file_info_label.pack(pady=5)
        
    def create_results_tabs(self):
        """Create tabbed results display"""
        self.tabview = ctk.CTkTabview(self.main_container)
        self.tabview.pack(fill="both", expand=True, pady=10)
        
        # Create tabs
        self.tabview.add("📊 Summary")
        self.tabview.add("⚠️ Suspicious APIs")
        self.tabview.add("🔍 Indicators")
        self.tabview.add("📦 PE Sections")
        self.tabview.add("📄 Full Report")
        
        # Setup each tab
        self.setup_summary_tab()
        self.setup_apis_tab()
        self.setup_indicators_tab()
        self.setup_sections_tab()
        self.setup_report_tab()
        
        # Initially disable tabs
        self.set_tabs_state("disabled")
        
    def setup_summary_tab(self):
        """Setup summary tab content"""
        tab = self.tabview.tab("📊 Summary")
        
        # Score frame
        score_frame = ctk.CTkFrame(tab)
        score_frame.pack(fill="x", pady=20, padx=20)
        
        self.score_label = ctk.CTkLabel(
            score_frame,
            text="Threat Score: 0/100",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        self.score_label.pack()
        
        # Score progress bar
        self.score_bar = ctk.CTkProgressBar(score_frame, width=400, height=20)
        self.score_bar.pack(pady=10)
        self.score_bar.set(0)
        
        # Verdict
        self.verdict_label = ctk.CTkLabel(
            score_frame,
            text="Verdict: Not Analyzed",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.verdict_label.pack(pady=10)
        
        # File details frame
        details_frame = ctk.CTkFrame(tab)
        details_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.file_details = ctk.CTkTextbox(details_frame, height=200, font=ctk.CTkFont(size=12))
        self.file_details.pack(fill="both", expand=True, padx=10, pady=10)
        
    def setup_apis_tab(self):
        """Setup suspicious APIs tab"""
        tab = self.tabview.tab("⚠️ Suspicious APIs")
        
        self.apis_text = ctk.CTkTextbox(tab, font=ctk.CTkFont(size=12))
        self.apis_text.pack(fill="both", expand=True, padx=20, pady=20)
        
    def setup_indicators_tab(self):
        """Setup indicators tab"""
        tab = self.tabview.tab("🔍 Indicators")
        
        self.indicators_text = ctk.CTkTextbox(tab, font=ctk.CTkFont(size=12))
        self.indicators_text.pack(fill="both", expand=True, padx=20, pady=20)
        
    def setup_sections_tab(self):
        """Setup PE sections tab"""
        tab = self.tabview.tab("📦 PE Sections")
        
        # Create frame for treeview
        tree_frame = ctk.CTkFrame(tab)
        tree_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Create treeview
        self.sections_tree = ttk.Treeview(
            tree_frame,
            columns=("Name", "Virtual Size", "Raw Size", "Entropy", "Status"),
            show="headings",
            height=15
        )
        
        # Define headings
        self.sections_tree.heading("Name", text="Section Name")
        self.sections_tree.heading("Virtual Size", text="Virtual Size")
        self.sections_tree.heading("Raw Size", text="Raw Size")
        self.sections_tree.heading("Entropy", text="Entropy")
        self.sections_tree.heading("Status", text="Status")
        
        # Set column widths
        self.sections_tree.column("Name", width=150)
        self.sections_tree.column("Virtual Size", width=120)
        self.sections_tree.column("Raw Size", width=120)
        self.sections_tree.column("Entropy", width=100)
        self.sections_tree.column("Status", width=150)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.sections_tree.yview)
        self.sections_tree.configure(yscrollcommand=scrollbar.set)
        
        self.sections_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
    def setup_report_tab(self):
        """Setup full report tab"""
        tab = self.tabview.tab("📄 Full Report")
        
        # Buttons container (now at the top)
        button_container = ctk.CTkFrame(tab, fg_color="transparent")
        button_container.pack(pady=10)
        
        # Export JSON button
        export_btn = ctk.CTkButton(
            button_container,
            text="💾 Export Report (JSON)",
            command=self.export_report,
            width=200,
            height=35
        )
        export_btn.pack(side="left", padx=10)
        
        # Export PDF button
        export_pdf_btn = ctk.CTkButton(
            button_container,
            text="📕 Export Report (PDF)",
            command=self.export_pdf_report,
            width=200,
            height=35,
            fg_color="#dc3545",
            hover_color="#c82333"
        )
        export_pdf_btn.pack(side="left", padx=10)

        # Report content (now below buttons)
        self.report_text = ctk.CTkTextbox(tab, font=ctk.CTkFont(size=11))
        self.report_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
    def create_status_bar(self):
        """Create status bar"""
        self.status_bar = ctk.CTkLabel(
            self.main_container,
            text=" Ready - Select a PE file to analyze",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        self.status_bar.pack(fill="x", pady=(10, 0))
        
    def setup_drag_drop(self):
        """Setup drag and drop functionality"""
        self.drop_area.bind("<Enter>", lambda e: self.drop_area.configure(fg_color="#3b3b3b"))
        self.drop_area.bind("<Leave>", lambda e: self.drop_area.configure(fg_color="#2b2b2b"))
        
    def browse_file(self):
        """Browse and select PE file"""
        file_path = filedialog.askopenfilename(
            title="Select PE File",
            filetypes=[
                ("Executable Files", "*.exe *.dll *.sys *.scr *.cpl"),
                ("All Files", "*.*")
            ]
        )
        
        if file_path:
            self.load_file(file_path)
            
    def load_file(self, file_path):
        """Load and validate PE file"""
        self.current_file = file_path
        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        
        # Update UI
        self.file_info_label.configure(
            text=f"📄 {filename} | Size: {file_size:,} bytes",
            text_color="#00d4ff"
        )
        
        # Enable analyze button
        self.analyze_btn.configure(state="normal")
        
        # Update status
        self.status_bar.configure(text=f" File loaded: {filename}")
        
        # Validate PE
        try:
            self.pe = pefile.PE(file_path)
            self.status_bar.configure(
                text=f" Valid PE file: {filename} | {self.pe.FILE_HEADER.NumberOfSections} sections"
            )
        except Exception as e:
            messagebox.showerror("Invalid File", f"Not a valid PE file:\n{str(e)}")
            self.reset_app()
            
    def start_analysis(self):
        """Start the analysis process"""
        if not self.current_file or not self.pe:
            messagebox.showwarning("No File", "Please select a PE file first")
            return
        
        # Disable buttons during analysis
        self.analyze_btn.configure(state="disabled")
        self.browse_btn.configure(state="disabled")
        
        # Start progress
        self.progress.start()
        
        # Update status
        self.status_bar.configure(text="🔍 Analyzing file... This may take a moment")
        
        # Run analysis in separate thread
        thread = threading.Thread(target=self.run_analysis, daemon=True)
        thread.start()
        
    def run_analysis(self):
        """Perform actual analysis (runs in background)"""
        try:
            results = {}
            
            # 1. Calculate hashes
            results['hashes'] = self.calculate_hashes()
            
            # 2. Parse headers
            results['headers'] = self.parse_headers()
            
            # 3. Analyze sections
            results['sections'] = self.analyze_sections()
            
            # 4. Get imports
            results['imports'], results['suspicious_apis'] = self.get_imports()
            
            # 5. Extract strings
            results['strings'] = self.extract_strings()
            
            # 6. Calculate threat score
            results['threat_score'] = self.calculate_threat_score(results)
            
            # 7. Determine verdict
            results['verdict'] = self.get_verdict(results['threat_score'])
            
            self.analysis_results = results
            
            # Save report automatically
            self.save_report(results)
            
            # Update UI in main thread
            self.root.after(0, self.display_results)
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Analysis Error", str(e)))
            
        finally:
            self.root.after(0, self.analysis_complete)
            
    def calculate_hashes(self):
        """Calculate file hashes"""
        with open(self.current_file, 'rb') as f:
            data = f.read()
            return {
                'md5': hashlib.md5(data).hexdigest(),
                'sha1': hashlib.sha1(data).hexdigest(),
                'sha256': hashlib.sha256(data).hexdigest()
            }
            
    def parse_headers(self):
        """Parse PE headers"""
        return {
            'machine': hex(self.pe.FILE_HEADER.Machine),
            'number_of_sections': self.pe.FILE_HEADER.NumberOfSections,
            'time_date_stamp': datetime.fromtimestamp(
                self.pe.FILE_HEADER.TimeDateStamp
            ).strftime('%Y-%m-%d %H:%M:%S'),
            'characteristics': hex(self.pe.FILE_HEADER.Characteristics),
            'entry_point': hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'image_base': hex(self.pe.OPTIONAL_HEADER.ImageBase),
            'subsystem': self.pe.OPTIONAL_HEADER.Subsystem
        }
        
    def analyze_sections(self):
        """Analyze PE sections for entropy"""
        sections = []
        for section in self.pe.sections:
            entropy = round(section.get_entropy(), 2)
            sections.append({
                'name': section.Name.decode().rstrip('\x00'),
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'entropy': entropy,
                'is_packed': entropy > 7.0
            })
        return sections
        
    def get_imports(self):
        """Extract imported functions"""
        imports = []
        suspicious_apis = []
        
        suspicious_list = {
            'Process Injection': ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
                                  'ReadProcessMemory', 'QueueUserAPC', 'SetThreadContext',
                                  'NtCreateThreadEx', 'OpenProcess'],
            'Keylogging': ['GetAsyncKeyState', 'SetWindowsHookEx', 'GetForegroundWindow',
                          'GetKeyState', 'GetKeyboardState', 'RegisterRawInputDevices'],
            'Network': ['URLDownloadToFile', 'InternetOpen', 'WSAStartup', 'HttpSendRequest',
                       'WinHttpOpen', 'socket', 'connect', 'send', 'recv', 'WSASocket'],
            'Persistence': ['RegSetValueEx', 'CreateService', 'SchTasks', 'CopyFile',
                           'MoveFileEx', 'CreateFile', 'RegCreateKeyEx'],
            'Evasion': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'OutputDebugString',
                       'NtQueryInformationProcess', 'GetTickCount', 'Sleep', 'VirtualProtect'],
            'Ransomware': ['CryptEncrypt', 'CryptDecrypt', 'FindFirstFile', 'DeleteFile',
                          'MoveFile', 'EncryptFile', 'FindNextFile']
        }
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode()
                        imports.append({'dll': dll_name, 'function': func_name})
                        
                        # Check if suspicious
                        for category, apis in suspicious_list.items():
                            if func_name in apis:
                                suspicious_apis.append({
                                    'category': category,
                                    'api': func_name,
                                    'dll': dll_name
                                })
                                break
                                
        return imports, suspicious_apis
        
    def extract_strings(self):
        """Extract readable strings from file"""
        strings = []
        urls = []
        ips = []
        file_paths = []
        
        # URL pattern
        url_pattern = re.compile(r'https?://[^\s]+|ftp://[^\s]+', re.IGNORECASE)
        # IP pattern
        ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        # File path pattern
        path_pattern = re.compile(r'[A-Za-z]:\\[^\s*?]+|C:\\[^\s*?]+')
        
        with open(self.current_file, 'rb') as f:
            data = f.read()
            # Extract ASCII strings (min 4 chars)
            ascii_strings = re.findall(b'[ -~]{4,}', data)
            
            for s in ascii_strings[:1000]:
                try:
                    decoded = s.decode('ascii', errors='ignore')
                    strings.append(decoded)
                    
                    # Check for URLs
                    urls.extend(url_pattern.findall(decoded))
                    
                    # Check for IPs
                    ips.extend(ip_pattern.findall(decoded))
                    
                    # Check for file paths
                    file_paths.extend(path_pattern.findall(decoded))
                    
                except:
                    pass
                    
        return {
            'total_strings': len(strings),
            'urls': list(set(urls))[:15],
            'ips': list(set(ips))[:15],
            'file_paths': list(set(file_paths))[:15],
            'sample_strings': strings[:50]
        }
        
    def calculate_threat_score(self, results):
        """Calculate overall threat score"""
        score = 0
        
        # Suspicious APIs (max 35)
        score += min(len(results['suspicious_apis']) * 12, 35)
        
        # Packed sections (entropy > 7.0) - max 20
        packed_count = sum(1 for s in results['sections'] if s['is_packed'])
        score += min(packed_count * 10, 20)
        
        # Network indicators - max 20
        network_indicators = len(results['strings']['urls']) + len(results['strings']['ips'])
        score += min(network_indicators * 5, 20)
        
        # Suspicious strings - max 15
        suspicious_keywords = ['http', '.exe', 'cmd', 'powershell', 'reg', 'admin', 
                               'password', 'key', 'log', 'steal', 'ransom']
        suspicious_count = 0
        for s in results['strings']['sample_strings']:
            if any(keyword in s.lower() for keyword in suspicious_keywords):
                suspicious_count += 1
        score += min(suspicious_count * 3, 15)
        
        # File paths (indicates file operations) - max 10
        score += min(len(results['strings']['file_paths']) * 3, 10)
        
        return min(score, 100)
        
    def get_verdict(self, score):
        """Get verdict based on score"""
        if score >= 70:
            return "MALICIOUS"
        elif score >= 40:
            return "SUSPICIOUS"
        else:
            return "CLEAN"
            
    def save_report(self, results):
        r"""Save analysis report to D:\PE_Analyzer\reports"""

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Use absolute path for reports folder in the current directory
            base_path = os.path.dirname(os.path.abspath(__file__))
            reports_dir = os.path.join(base_path, "reports")
            
            # Create reports folder if it doesn't exist
            if not os.path.exists(reports_dir):
                os.makedirs(reports_dir)
                
            filename = os.path.join(reports_dir, f"report_{timestamp}.json")
            
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
                
            self.status_bar.configure(text=f" Report saved to: {filename}")
        except Exception as e:
            print(f"Could not save report: {e}")
            
    def display_results(self):
        """Display analysis results in UI"""
        if not self.analysis_results:
            return
            
        results = self.analysis_results
        
        # Update score display
        score = results['threat_score']
        self.score_label.configure(text=f"Threat Score: {score}/100")
        self.score_bar.set(score / 100)
        
        # Set color based on score
        if score >= 70:
            color = "#dc3545"
        elif score >= 40:
            color = "#ffc107"
        else:
            color = "#28a745"
            
        self.score_label.configure(text_color=color)
        self.verdict_label.configure(text_color=color)
        
        # Update verdict
        verdict = results['verdict']
        verdict_icon = "🔴" if verdict == "MALICIOUS" else "🟡" if verdict == "SUSPICIOUS" else "🟢"
        self.verdict_label.configure(text=f"{verdict_icon} Verdict: {verdict}")
        
        # File details
        file_details = f"""
{'='*55}
PE FILE ANALYSIS REPORT
{'='*55}

📁 FILE INFORMATION:
   • Filename: {os.path.basename(self.current_file)}
   • Size: {os.path.getsize(self.current_file):,} bytes
   • Path: {self.current_file}

🔐 HASHES:
   • MD5: {results['hashes']['md5']}
   • SHA1: {results['hashes']['sha1']}
   • SHA256: {results['hashes']['sha256']}

📋 PE HEADER:
   • Machine: {results['headers']['machine']}
   • Sections: {results['headers']['number_of_sections']}
   • Compilation: {results['headers']['time_date_stamp']}
   • Entry Point: {results['headers']['entry_point']}
   • Image Base: {results['headers']['image_base']}

📊 ANALYSIS SUMMARY:
   • Threat Score: {results['threat_score']}/100
   • Verdict: {results['verdict']}
   • Suspicious APIs: {len(results['suspicious_apis'])}
   • Packed Sections: {sum(1 for s in results['sections'] if s['is_packed'])}
   • URLs Found: {len(results['strings']['urls'])}
   • IPs Found: {len(results['strings']['ips'])}
   • File Paths: {len(results['strings']['file_paths'])}

{'='*55}
"""

        self.file_details.delete("1.0", "end")
        self.file_details.insert("1.0", file_details)
        
        # Suspicious APIs
        if results['suspicious_apis']:
            apis_text = "⚠️ SUSPICIOUS APIs DETECTED ⚠️\n" + "="*50 + "\n\n"
            for api in results['suspicious_apis']:
                apis_text += f"[!] {api['category']}\n"
                apis_text += f"    └─ API: {api['api']}\n"
                apis_text += f"    └─ DLL: {api['dll']}\n\n"
        else:
            apis_text = " No suspicious APIs detected.\n\nThe file does not contain any known malicious API patterns."

            
        self.apis_text.delete("1.0", "end")
        self.apis_text.insert("1.0", apis_text)
        
        # Indicators
        indicators_text = "🔍 EXTRACTED INDICATORS\n" + "="*50 + "\n\n"
        
        if results['strings']['urls']:
            indicators_text += "🌐 URLs Found:\n"
            for url in results['strings']['urls']:
                indicators_text += f"   • {url}\n"
            indicators_text += "\n"
            
        if results['strings']['ips']:
            indicators_text += "📍 IP Addresses Found:\n"
            for ip in results['strings']['ips']:
                indicators_text += f"   • {ip}\n"
            indicators_text += "\n"
            
        if results['strings']['file_paths']:
            indicators_text += "📂 File Paths Found:\n"
            for path in results['strings']['file_paths']:
                indicators_text += f"   • {path}\n"
            indicators_text += "\n"
            
        if results['strings']['sample_strings']:
            indicators_text += "📝 Interesting Strings (First 20):\n"
            for s in results['strings']['sample_strings'][:20]:
                if len(s) > 4 and any(c.isalnum() for c in s):
                    indicators_text += f"   • {s[:80]}\n"

                    
        self.indicators_text.delete("1.0", "end")
        self.indicators_text.insert("1.0", indicators_text)
        
        # Sections
        for item in self.sections_tree.get_children():
            self.sections_tree.delete(item)
            
        for section in results['sections']:
            status = "⚠️ PACKED/ENCRYPTED" if section['is_packed'] else " NORMAL"
            tag = 'packed' if section['is_packed'] else 'normal'
            
            self.sections_tree.insert("", "end", values=(
                section['name'],
                f"{section['virtual_size']:,}",
                f"{section['raw_size']:,}",
                f"{section['entropy']:.2f}",
                status
            ), tags=(tag,))
            
        # Configure tags for colors
        self.sections_tree.tag_configure('packed', foreground='#ff6b6b')
        self.sections_tree.tag_configure('normal', foreground='#51cf66')
        
        # Full report
        self.report_text.delete("1.0", "end")
        self.report_text.insert("1.0", json.dumps(results, indent=2, default=str))
        
        # Enable tabs
        self.set_tabs_state("normal")
        
    def set_tabs_state(self, state):
        """Enable or disable tabs"""
        try:
            if state == "normal":
                self.tabview._segmented_button.configure(state="normal")
            else:
                self.tabview._segmented_button.configure(state="disabled")
        except:
            pass
            
    def analysis_complete(self):
        """Called when analysis is complete"""
        self.progress.stop()
        self.progress.set(0)
        self.analyze_btn.configure(state="normal")
        self.browse_btn.configure(state="normal")
        self.status_bar.configure(text=" Analysis complete! Review results in tabs above")
        
    def export_report(self):
        """Export analysis report to JSON"""
        if not self.analysis_results:
            messagebox.showwarning("No Report", "No analysis results to export")
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"pe_analysis_{timestamp}.json"
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile=filename
        )
        
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(self.analysis_results, f, indent=2, default=str)
            messagebox.showinfo("Export Successful", f"Report saved to:\n{file_path}")

    def export_pdf_report(self):
        """Export analysis report to PDF"""
        if not self.analysis_results:
            messagebox.showwarning("No Report", "No analysis results to export")
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"pe_analysis_report_{timestamp}.pdf"
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            initialfile=filename
        )
        
        if file_path:
            try:
                self.generate_pdf(file_path)
                messagebox.showinfo("Export Successful", f"PDF Report saved to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Could not generate PDF: {str(e)}")

    def generate_pdf(self, file_path):
        """Generate PDF report using fpdf2"""
        results = self.analysis_results
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font("Arial", 'B', 20)
        pdf.set_text_color(0, 212, 255)  # Cyan color
        pdf.cell(0, 15, "PE FILE STATIC ANALYSIS REPORT", 0, 1, 'C')
        pdf.set_text_color(0, 0, 0)
        
        pdf.set_font("Arial", 'I', 10)
        pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'R')
        pdf.ln(10)
        
        # 1. FILE INFORMATION
        pdf.set_font("Arial", 'B', 14)
        pdf.set_fill_color(240, 240, 240)
        pdf.cell(0, 10, " 1. FILE INFORMATION", 0, 1, 'L', True)
        pdf.ln(2)
        
        pdf.set_font("Courier", size=10)
        pdf.cell(0, 7, f"Filename:    {os.path.basename(self.current_file)}", 0, 1)
        pdf.cell(0, 7, f"File Size:   {os.path.getsize(self.current_file):,} bytes", 0, 1)
        pdf.cell(0, 7, f"File Path:   {self.current_file}", 0, 1)
        pdf.ln(5)
        
        # 2. ANALYSIS VERDICT
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, " 2. ANALYSIS VERDICT", 0, 1, 'L', True)
        pdf.ln(2)
        
        score = results['threat_score']
        verdict = results['verdict']
        
        if score >= 70:
            pdf.set_text_color(220, 53, 69)  # Red
        elif score >= 40:
            pdf.set_text_color(255, 193, 7)  # Yellow/Amber
        else:
            pdf.set_text_color(40, 167, 69)  # Green
            
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(0, 10, f"Verdict: {verdict}", 0, 1)
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 7, f"Threat Score: {score}/100", 0, 1)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(5)
        
        # 3. HASHES
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, " 3. FILE HASHES", 0, 1, 'L', True)
        pdf.ln(2)
        pdf.set_font("Courier", size=10)
        pdf.cell(0, 7, f"MD5:    {results['hashes']['md5']}", 0, 1)
        pdf.cell(0, 7, f"SHA1:   {results['hashes']['sha1']}", 0, 1)
        pdf.cell(0, 7, f"SHA256: {results['hashes']['sha256']}", 0, 1)
        pdf.ln(5)
        
        # 4. SUSPICIOUS APIS
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, " 4. SUSPICIOUS APIS", 0, 1, 'L', True)
        pdf.ln(2)
        
        if results['suspicious_apis']:
            pdf.set_font("Arial", 'B', 10)
            pdf.cell(60, 8, "Category", 1)
            pdf.cell(60, 8, "API Name", 1)
            pdf.cell(60, 8, "Source DLL", 1)
            pdf.ln()
            
            pdf.set_font("Arial", size=9)
            for api in results['suspicious_apis']:
                pdf.cell(60, 7, str(api['category']), 1)
                pdf.cell(60, 7, str(api['api']), 1)
                pdf.cell(60, 7, str(api['dll']), 1)
                pdf.ln()
        else:
            pdf.set_font("Arial", size=10)
            pdf.cell(0, 7, "No suspicious APIs detected.", 0, 1)
        pdf.ln(5)
        
        # 5. PE SECTIONS
        if pdf.get_y() > 250: pdf.add_page()
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, " 5. PE SECTIONS", 0, 1, 'L', True)
        pdf.ln(2)
        
        pdf.set_font("Arial", 'B', 10)
        pdf.cell(30, 8, "Name", 1)
        pdf.cell(40, 8, "Virtual Size", 1)
        pdf.cell(40, 8, "Raw Size", 1)
        pdf.cell(30, 8, "Entropy", 1)
        pdf.cell(50, 8, "Status", 1)
        pdf.ln()
        
        pdf.set_font("Arial", size=9)
        for section in results['sections']:
            status = "PACKED" if section['is_packed'] else "NORMAL"
            pdf.cell(30, 7, section['name'], 1)
            pdf.cell(40, 7, f"{section['virtual_size']:,}", 1)
            pdf.cell(40, 7, f"{section['raw_size']:,}", 1)
            pdf.cell(30, 7, f"{section['entropy']:.2f}", 1)
            pdf.cell(50, 7, status, 1)
            pdf.ln()
        pdf.ln(5)
        
        # 6. EXTRACTED INDICATORS
        if pdf.get_y() > 220: pdf.add_page()
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, " 6. EXTRACTED INDICATORS", 0, 1, 'L', True)
        pdf.ln(2)
        
        # URLs
        if results['strings']['urls']:
            pdf.set_font("Arial", 'B', 11)
            pdf.cell(0, 8, "URLs Found:", 0, 1)
            pdf.set_font("Courier", size=9)
            for url in results['strings']['urls']:
                pdf.cell(0, 6, f" - {url}", 0, 1)
            pdf.ln(2)
            
        # IPs
        if results['strings']['ips']:
            pdf.set_font("Arial", 'B', 11)
            pdf.cell(0, 8, "IP Addresses Found:", 0, 1)
            pdf.set_font("Courier", size=9)
            for ip in results['strings']['ips']:
                pdf.cell(0, 6, f" - {ip}", 0, 1)
            pdf.ln(2)
            
        # File Paths
        if results['strings']['file_paths']:
            pdf.set_font("Arial", 'B', 11)
            pdf.cell(0, 8, "File Paths Found:", 0, 1)
            pdf.set_font("Courier", size=9)
            for path in results['strings']['file_paths']:
                pdf.cell(0, 6, f" - {path}", 0, 1)
            pdf.ln(2)
            
        # Strings
        if results['strings']['sample_strings']:
            pdf.set_font("Arial", 'B', 11)
            pdf.cell(0, 8, "Interesting Strings (Top 10):", 0, 1)
            pdf.set_font("Courier", size=8)
            for s in results['strings']['sample_strings'][:10]:
                if len(s) > 4:
                    # Clean string for PDF compatibility
                    clean_s = "".join(c for c in s if ord(c) < 128)
                    pdf.cell(0, 5, f" - {clean_s[:90]}", 0, 1)
        
        # Save the PDF
        pdf.output(file_path)

            
    def reset_app(self):
        """Reset the application"""
        self.current_file = None
        self.pe = None
        self.analysis_results = None
        
        self.file_info_label.configure(text="No file selected", text_color="gray")
        self.analyze_btn.configure(state="disabled")
        self.status_bar.configure(text=" Ready - Select a PE file to analyze")
        
        # Clear displays
        self.file_details.delete("1.0", "end")
        self.apis_text.delete("1.0", "end")
        self.indicators_text.delete("1.0", "end")
        self.report_text.delete("1.0", "end")
        
        for item in self.sections_tree.get_children():
            self.sections_tree.delete(item)
            
        self.score_label.configure(text="Threat Score: 0/100")
        self.score_bar.set(0)
        self.verdict_label.configure(text="Verdict: Not Analyzed")
        self.verdict_label.configure(text_color="gray")

if __name__ == "__main__":
    app = PEAnalyzerApp()
    app.root.mainloop()
