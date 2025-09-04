import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from firewall_engine import Firewall, Packet, FirewallRule, Action, Protocol
import threading
import time
import random

class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Firewall Simulator")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2c3e50')
        
        self.firewall = Firewall()
        self.simulation_running = False
        
        self.create_widgets()
        self.load_default_rules()

    def create_widgets(self):
        # Main title
        title_label = tk.Label(self.root, text="🔥 FIREWALL SIMULATOR 🔥", 
                              font=('Arial', 20, 'bold'), 
                              bg='#2c3e50', fg='#ecf0f1')
        title_label.pack(pady=10)

        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Rules Tab
        self.rules_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.rules_frame, text='🛡️ Firewall Rules')
        self.create_rules_tab()

        # Monitor Tab
        self.monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.monitor_frame, text='📊 Traffic Monitor')
        self.create_monitor_tab()

        # Statistics Tab
        self.stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stats_frame, text='📈 Statistics')
        self.create_stats_tab()

    def create_rules_tab(self):
        # Rules management section
        rules_label_frame = ttk.LabelFrame(self.rules_frame, text="Firewall Rules Management", padding=10)
        rules_label_frame.pack(fill='x', padx=10, pady=5)

        # Add rule section
        add_frame = ttk.Frame(rules_label_frame)
        add_frame.pack(fill='x', pady=5)

        ttk.Label(add_frame, text="Rule Name:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.rule_name_entry = ttk.Entry(add_frame, width=15)
        self.rule_name_entry.grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(add_frame, text="Action:").grid(row=0, column=2, padx=5, pady=2, sticky='w')
        self.action_combo = ttk.Combobox(add_frame, values=['ALLOW', 'BLOCK'], width=10)
        self.action_combo.grid(row=0, column=3, padx=5, pady=2)
        self.action_combo.set('BLOCK')

        ttk.Label(add_frame, text="Source IP:").grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.src_ip_entry = ttk.Entry(add_frame, width=15)
        self.src_ip_entry.grid(row=1, column=1, padx=5, pady=2)

        ttk.Label(add_frame, text="Dest IP:").grid(row=1, column=2, padx=5, pady=2, sticky='w')
        self.dest_ip_entry = ttk.Entry(add_frame, width=15)
        self.dest_ip_entry.grid(row=1, column=3, padx=5, pady=2)

        ttk.Label(add_frame, text="Source Port:").grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.src_port_entry = ttk.Entry(add_frame, width=15)
        self.src_port_entry.grid(row=2, column=1, padx=5, pady=2)

        ttk.Label(add_frame, text="Dest Port:").grid(row=2, column=2, padx=5, pady=2, sticky='w')
        self.dest_port_entry = ttk.Entry(add_frame, width=15)
        self.dest_port_entry.grid(row=2, column=3, padx=5, pady=2)

        ttk.Label(add_frame, text="Protocol:").grid(row=3, column=0, padx=5, pady=2, sticky='w')
        self.protocol_combo = ttk.Combobox(add_frame, values=['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS'], width=10)
        self.protocol_combo.grid(row=3, column=1, padx=5, pady=2)

        ttk.Button(add_frame, text="Add Rule", command=self.add_rule).grid(row=3, column=2, padx=10, pady=5)
        ttk.Button(add_frame, text="Remove Selected", command=self.remove_rule).grid(row=3, column=3, padx=5, pady=5)

        # Rules list
        self.rules_tree = ttk.Treeview(self.rules_frame, columns=('Action', 'Src IP', 'Dest IP', 'Src Port', 'Dest Port', 'Protocol'), show='tree headings')
        self.rules_tree.heading('#0', text='Rule Name')
        self.rules_tree.heading('Action', text='Action')
        self.rules_tree.heading('Src IP', text='Source IP')
        self.rules_tree.heading('Dest IP', text='Dest IP')
        self.rules_tree.heading('Src Port', text='Src Port')
        self.rules_tree.heading('Dest Port', text='Dest Port')
        self.rules_tree.heading('Protocol', text='Protocol')
        
        self.rules_tree.pack(fill='both', expand=True, padx=10, pady=10)

    def create_monitor_tab(self):
        # Control buttons
        control_frame = ttk.Frame(self.monitor_frame)
        control_frame.pack(fill='x', padx=10, pady=5)

        self.start_button = ttk.Button(control_frame, text="🚀 Start Simulation", command=self.start_simulation)
        self.start_button.pack(side='left', padx=5)

        self.stop_button = ttk.Button(control_frame, text="⏹️ Stop Simulation", command=self.stop_simulation)
        self.stop_button.pack(side='left', padx=5)

        ttk.Button(control_frame, text="🗑️ Clear Logs", command=self.clear_logs).pack(side='left', padx=5)

        # Traffic display
        self.traffic_text = scrolledtext.ScrolledText(self.monitor_frame, height=25, bg='#34495e', fg='#ecf0f1', font=('Courier', 10))
        self.traffic_text.pack(fill='both', expand=True, padx=10, pady=10)

    def create_stats_tab(self):
        # Statistics display
        stats_frame = ttk.LabelFrame(self.stats_frame, text="Real-time Statistics", padding=10)
        stats_frame.pack(fill='x', padx=10, pady=10)

        self.stats_labels = {}
        stats_info = [
            ('Total Packets:', 'total_packets'),
            ('Allowed Packets:', 'allowed_packets'),
            ('Blocked Packets:', 'blocked_packets'),
            ('Active Rules:', 'total_rules'),
            ('Block Rate:', 'block_rate')
        ]

        for i, (label, key) in enumerate(stats_info):
            ttk.Label(stats_frame, text=label, font=('Arial', 12, 'bold')).grid(row=i, column=0, sticky='w', padx=10, pady=5)
            self.stats_labels[key] = ttk.Label(stats_frame, text="0", font=('Arial', 12), foreground='#2980b9')
            self.stats_labels[key].grid(row=i, column=1, sticky='w', padx=20, pady=5)

        # Packet log
        log_frame = ttk.LabelFrame(self.stats_frame, text="Recent Packet Log", padding=10)
        log_frame.pack(fill='both', expand=True, padx=10, pady=10)

        self.packet_tree = ttk.Treeview(log_frame, columns=('Time', 'Source', 'Destination', 'Protocol', 'Action'), show='headings')
        self.packet_tree.heading('Time', text='Time')
        self.packet_tree.heading('Source', text='Source')
        self.packet_tree.heading('Destination', text='Destination')
        self.packet_tree.heading('Protocol', text='Protocol')
        self.packet_tree.heading('Action', text='Action')
        
        self.packet_tree.pack(fill='both', expand=True)

    def load_default_rules(self):
        # Load some default rules
        default_rules = [
            FirewallRule("Block Malicious IP", Action.BLOCK, src_ip="192.168.1.100"),
            FirewallRule("Block Telnet", Action.BLOCK, dest_port=23),
            FirewallRule("Allow HTTP", Action.ALLOW, dest_port=80),
            FirewallRule("Allow HTTPS", Action.ALLOW, dest_port=443),
            FirewallRule("Block FTP", Action.BLOCK, dest_port=21),
        ]

        for rule in default_rules:
            self.firewall.add_rule(rule)
        
        self.refresh_rules_display()

    def add_rule(self):
        rule_name = self.rule_name_entry.get()
        if not rule_name:
            messagebox.showerror("Error", "Please enter a rule name")
            return

        action = Action.ALLOW if self.action_combo.get() == 'ALLOW' else Action.BLOCK
        
        # Get optional fields
        src_ip = self.src_ip_entry.get() or None
        dest_ip = self.dest_ip_entry.get() or None
        src_port = int(self.src_port_entry.get()) if self.src_port_entry.get() else None
        dest_port = int(self.dest_port_entry.get()) if self.dest_port_entry.get() else None
        protocol = self.protocol_combo.get() or None

        rule = FirewallRule(rule_name, action, src_ip, dest_ip, src_port, dest_port, protocol)
        self.firewall.add_rule(rule)
        
        self.refresh_rules_display()
        self.clear_rule_entries()

    def remove_rule(self):
        selection = self.rules_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a rule to remove")
            return
        
        rule_name = self.rules_tree.item(selection[0])['text']
        self.firewall.remove_rule(rule_name)
        self.refresh_rules_display()

    def refresh_rules_display(self):
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
        
        for rule in self.firewall.rules:
            self.rules_tree.insert('', 'end', text=rule.rule_name, values=(
                rule.action.value,
                rule.src_ip or 'Any',
                rule.dest_ip or 'Any',
                rule.src_port or 'Any',
                rule.dest_port or 'Any',
                rule.protocol or 'Any'
            ))

    def clear_rule_entries(self):
        self.rule_name_entry.delete(0, tk.END)
        self.src_ip_entry.delete(0, tk.END)
        self.dest_ip_entry.delete(0, tk.END)
        self.src_port_entry.delete(0, tk.END)
        self.dest_port_entry.delete(0, tk.END)
        self.protocol_combo.set('')

    def start_simulation(self):
        self.simulation_running = True
        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        
        # Start simulation thread
        self.simulation_thread = threading.Thread(target=self.simulate_traffic)
        self.simulation_thread.daemon = True
        self.simulation_thread.start()

    def stop_simulation(self):
        self.simulation_running = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')

    def simulate_traffic(self):
        sample_ips = ['192.168.1.10', '10.0.0.5', '8.8.8.8', '192.168.1.100', '172.16.0.10']
        sample_ports = [80, 443, 22, 23, 21, 25, 53, 8080, 3389]
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'ICMP']

        while self.simulation_running:
            # Generate random packet
            packet = Packet(
                src_ip=random.choice(sample_ips),
                dest_ip=random.choice(sample_ips),
                src_port=random.randint(1024, 65535),
                dest_port=random.choice(sample_ports),
                protocol=random.choice(protocols)
            )

            action, rule_name = self.firewall.process_packet(packet)
            
            # Update GUI
            self.root.after(0, self.update_traffic_display, packet, action, rule_name)
            self.root.after(0, self.update_statistics)
            
            time.sleep(random.uniform(0.5, 2.0))  # Random delay

    def update_traffic_display(self, packet, action, rule_name):
        color = '#e74c3c' if action == Action.BLOCK else '#27ae60'
        status = f"[{action.value}] by rule '{rule_name}'"
        
        self.traffic_text.insert(tk.END, f"{packet} - {status}\n")
        self.traffic_text.tag_add(action.value, "end-2l", "end-1l")
        self.traffic_text.tag_config(Action.BLOCK.value, foreground='#e74c3c')
        self.traffic_text.tag_config(Action.ALLOW.value, foreground='#27ae60')
        self.traffic_text.see(tk.END)

        # Add to packet log
        self.packet_tree.insert('', 0, values=(
            packet.timestamp.strftime('%H:%M:%S'),
            f"{packet.src_ip}:{packet.src_port}",
            f"{packet.dest_ip}:{packet.dest_port}",
            packet.protocol,
            action.value
        ))

        # Keep only last 100 entries
        children = self.packet_tree.get_children()
        if len(children) > 100:
            self.packet_tree.delete(children[-1])

    def update_statistics(self):
        stats = self.firewall.get_statistics()
        
        self.stats_labels['total_packets'].config(text=str(stats['total_packets']))
        self.stats_labels['allowed_packets'].config(text=str(stats['allowed_packets']))
        self.stats_labels['blocked_packets'].config(text=str(stats['blocked_packets']))
        self.stats_labels['total_rules'].config(text=str(stats['total_rules']))
        
        # Calculate block rate
        if stats['total_packets'] > 0:
            block_rate = (stats['blocked_packets'] / stats['total_packets']) * 100
            self.stats_labels['block_rate'].config(text=f"{block_rate:.1f}%")
        else:
            self.stats_labels['block_rate'].config(text="0%")

    def clear_logs(self):
        self.traffic_text.delete(1.0, tk.END)
        self.firewall.allowed_packets.clear()
        self.firewall.blocked_packets.clear()
        
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()
