import scapy.all as scapy
import psutil
import threading
import tkinter as tk
from tkinter import ttk, Toplevel, messagebox
from scapy.layers.inet import TCP, UDP, IP, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RA

import string

class PacketSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("Albus Richard's Network Packet Sniffer")
        self.root.geometry("1200x600")  # 设置宽度为1200，高度为800
        self.filter_protocol = tk.StringVar(value="All")
        self.filter_IP = tk.StringVar(value="All")
        self.sniffing = False
        self.packet_count = 0  # Packet counter for No column
        self.start_time = None  # Base time for the first packet

        # Store captured packets for detailed view
        self.captured_packets = []
        self.displayed_packets = []
        # Set up GUI elements
        self.create_widgets()

    def create_widgets(self):
        # 控制按钮和下拉菜单的框架
        control_frame = tk.Frame(self.root)
        control_frame.pack(fill=tk.X, pady=5)

        # Start and Stop buttons
        start_button = tk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing)
        start_button.pack(side=tk.LEFT, padx=5)

        stop_button = tk.Button(control_frame, text="Stop Sniffing", command=self.stop_sniffing)
        stop_button.pack(side=tk.LEFT, padx=5)

        protocol_label_ip = tk.Label(control_frame, text="IP Filter:")
        protocol_label_ip.pack(side=tk.LEFT, padx=5)
        protocol_options_ip = ["All", "IPv4", "IPv6"]
        protocol_menu_ip = ttk.Combobox(control_frame, textvariable=self.filter_IP, values=protocol_options_ip)
        protocol_menu_ip.pack(side=tk.LEFT, padx=5)
        protocol_menu_ip.bind("<<ComboboxSelected>>", self.apply_filter)

        # Protocol filter dropdown
        protocol_label = tk.Label(control_frame, text="Protocol Filter:")
        protocol_label.pack(side=tk.LEFT, padx=5)

        protocol_options = ["All", "TCP", "UDP", "HTTP", "ICMP", "DNS", "TLS"]
        protocol_menu = ttk.Combobox(control_frame, textvariable=self.filter_protocol, values=protocol_options)
        protocol_menu.pack(side=tk.LEFT, padx=5)
        # Assuming protocol_menu is a ttk.Combobox
        protocol_menu.bind("<<ComboboxSelected>>", self.apply_filter)

        # 主框架，用于放置 packet_tree 和显示内容
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Treeview 显示数据包信息
        columns = ("No", "Time", "Source", "Destination", "IP", "Protocol", "Length", "Info")
        self.packet_tree = ttk.Treeview(main_frame, columns=columns, show="headings", height=10)
        self.packet_tree.grid(row=0, column=0, columnspan=2, sticky="nsew")
        self.packet_tree.bind("<ButtonRelease-1>", self.show_packet_details)  # 绑定点击事件

        # 在 packet_tree 上绑定右键菜单
        self.packet_tree.bind("<Button-3>", self.show_context_menu)

        # 定义 Treeview 的列宽
        self.packet_tree.column("No", width=30, anchor="center")
        self.packet_tree.column("Time", width=60, anchor="center")
        self.packet_tree.column("Source", width=100, anchor="center")
        self.packet_tree.column("Destination", width=100, anchor="center")
        self.packet_tree.column("IP", width=40, anchor="center")
        self.packet_tree.column("Protocol", width=60, anchor="center")
        self.packet_tree.column("Length", width=50, anchor="center")
        self.packet_tree.column("Info", width=300, anchor="w")

        for col in columns:
            self.packet_tree.heading(col, text=col)

        # Treeview 的垂直滚动条
        tree_scroll = ttk.Scrollbar(main_frame, orient="vertical", command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=tree_scroll.set)
        tree_scroll.grid(row=0, column=2, sticky="ns")

        # Frame for Raw Packet Data and Offset Label
        raw_frame = tk.Frame(main_frame)
        raw_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)

        # Text box for Offset Label
        self.offset_text = tk.Text(raw_frame, width=5, height=10, wrap="none", bg="#f0f0f0", fg="black")
        self.offset_text.pack(side=tk.LEFT, fill=tk.Y)
        self.offset_text.configure(state="disabled")  # 设置为只读

        # Text box for Raw Packet Data
        self.raw_text = tk.Text(raw_frame, height=10, wrap="none")
        self.raw_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 设置同步滚动
        raw_scroll = tk.Scrollbar(raw_frame, orient="vertical", command=self.sync_scroll)
        raw_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.raw_text.configure(yscrollcommand=raw_scroll.set)
        self.offset_text.configure(yscrollcommand=raw_scroll.set)

        # Frame for Parsed Packet Data to the right of packet_tree and raw_frame
        # parsed_frame = tk.Frame(main_frame)
        parsed_frame = tk.Frame(main_frame, width=200)
        parsed_frame.grid_propagate(False)
        parsed_frame.grid(row=0, column=3, rowspan=2, sticky="nsew", padx=5, pady=5)

        # Label for Parsed Packet Data
        parsed_label = tk.Label(parsed_frame, text="Parsed Packet Data:")
        parsed_label.pack(anchor="w")

        # Text box for Parsed Packet Data
        self.parsed_text = tk.Text(parsed_frame, width=30, height=20, wrap="none")
        self.parsed_text.pack(fill=tk.BOTH, expand=True)

        # 配置主框架的网格布局
        self.packet_tree.grid(row=0, column=0, columnspan=2, sticky="nsew")  # packet_tree 占据两列
        main_frame.columnconfigure(0, weight=4)  # packet_tree 和 raw_frame 的列
        main_frame.columnconfigure(3, weight=1)  # parsed_frame 列
        main_frame.rowconfigure(0, weight=3)  # packet_tree 的行
        main_frame.rowconfigure(1, weight=1)  # raw_frame 的行

    def sync_scroll(self, *args):
        # 同步滚动 offset_text 和 raw_text
        self.raw_text.yview(*args)
        self.offset_text.yview(*args)
        self.raw_text.yview_moveto(args[0])

    def start_sniffing(self):
        self.sniffing = True
        print("start sniffing")
        self.packet_tree.delete(*self.packet_tree.get_children())  # Clear existing entries
        self.captured_packets.clear()  # Clear captured packets
        self.packet_count = 0
        self.start_time = None  # Reset start time
        sniff_thread = threading.Thread(target=self.sniff_packets)
        sniff_thread.start()
        self.displayed_packets.clear()

    def stop_sniffing(self):
        self.sniffing = False
        print("stop sniffing")

    def sniff_packets(self):
        try:
            scapy.sniff(prn=self.process_packet, stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            print(f"Error during sniffing: {e}")

    def process_packet(self, packet):
        try:
            # Set base time for the first packet
            if self.start_time is None:
                self.start_time = packet.time

            # Calculate relative timestamp
            self.packet_count += 1
            timestamp = round(packet.time - self.start_time, 6)

            # Set default values for Source, Destination, and Protocol
            source, destination, protocol_name , ip_n = "N/A", "N/A", "Unknown", "Unknown"
            info = packet.summary()

            # Identify IP layer (IPv4 or IPv6)
            if IP in packet:
                source = packet[IP].src
                destination = packet[IP].dst
                protocol_name = "IPv4"
                ip_n = "IPv4"
            elif IPv6 in packet:
                source = packet[IPv6].src
                destination = packet[IPv6].dst
                protocol_name = "IPv6"
                ip_n = "IPv6"

                # Detect ICMPv6 messages within IPv6 packets
                if packet.haslayer(ICMPv6EchoRequest):
                    protocol_name = "ICMP"
                    info = f"ICMPv6 Echo Request ID={packet[ICMPv6EchoRequest].id} Seq={packet[ICMPv6EchoRequest].seq}"
                elif packet.haslayer(ICMPv6EchoReply):
                    protocol_name = "ICMP"
                    info = f"ICMPv6 Echo Reply ID={packet[ICMPv6EchoReply].id} Seq={packet[ICMPv6EchoReply].seq}"
                elif packet.haslayer(ICMPv6ND_NS):  # Neighbor Solicitation
                    protocol_name = "ICMP"
                    info = f"Neighbor Solicitation Target={packet[ICMPv6ND_NS].tgt}"
                elif packet.haslayer(ICMPv6ND_NA):  # Neighbor Advertisement
                    protocol_name = "ICMP"
                    info = f"Neighbor Advertisement Target={packet[ICMPv6ND_NA].tgt}"
                elif packet.haslayer(ICMPv6ND_RA):  # Router Advertisement
                    protocol_name = "ICMP"
                    info = "Router Advertisement"

            elif ARP in packet:
                source = packet[ARP].psrc
                destination = packet[ARP].pdst
                protocol_name = "ARP"

            elif not (IP in packet or IPv6 in packet or ARP in packet):
                print("Packet does not contain expected layers.")

            # Detect and parse specific protocols (e.g., TCP, UDP)
            if TCP in packet:
                protocol_name = "TCP"
                info = f"{packet[TCP].sport} -> {packet[TCP].dport} [Flags={packet.sprintf('%TCP.flags%')}] Seq={packet[TCP].seq} Ack={packet[TCP].ack}"
                # Check if the packet is likely to be TLS by port number (443)
                if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    protocol_name = "TLS"
                    info = "TLS Packet on port 443"

                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    if packet.haslayer(HTTPRequest):
                        protocol_name = "HTTP"
                        info = f"HTTP Request: {packet[HTTPRequest].Method.decode()} {packet[HTTPRequest].Host.decode()}{packet[HTTPRequest].Path.decode()}"
                    elif packet.haslayer(HTTPResponse):
                        protocol_name = "HTTP"
                        info = f"HTTP Response: Status Code {packet[HTTPResponse].Status_Code.decode()}"

            elif UDP in packet:
                protocol_name = "UDP"
                info = f"{packet[UDP].sport} -> {packet[UDP].dport}"
                # Check if the packet is likely to be DNS
                if packet.haslayer(DNS):
                    protocol_name = "DNS"
                    if packet[DNS].qr == 0:  # Query
                        info = f"DNS Query: {packet[DNSQR].qname.decode()}"
                    else:  # Response
                        info = "DNS Response"
                        if packet[DNS].ancount > 0:  # If there are answers
                            answers = [packet[DNSRR][i].rdata for i in range(packet[DNS].ancount)]
                            info += f" - Answers: {answers}"

            elif ICMP in packet and protocol_name != "ICMP":
                # Only handle standard ICMP if not IPv6 (i.e., avoid double-counting)
                protocol_name = "ICMP"
                info = f"Type={packet[ICMP].type} Code={packet[ICMP].code} ID={packet[ICMP].id} Seq={packet[ICMP].seq}"

            # Save the packet for detailed view and update the Treeview
            self.captured_packets.append(packet)
            length = len(packet)
            self.displayed_packets.append(
                (self.packet_count, timestamp, source, destination, ip_n, protocol_name, length, info, packet)
            )
            self.packet_tree.insert("", "end",
                                    values=(self.packet_count, timestamp, source, destination, ip_n, protocol_name, length, info))
        except Exception as e:
            print(f"Error processing packet: {e}, Packet: {packet.summary()}")


    def show_packet_details(self, event):
        # 获取选中的数据包
        selected_item = self.packet_tree.selection()
        if not selected_item:
            return
        item_index = int(self.packet_tree.item(selected_item)['values'][0]) - 1  # 从 No 列获取数据包索引

        # 获取对应的数据包
        packet = self.captured_packets[item_index]
        raw_bytes = bytes(packet)  # 原始字节数据

        # 显示偏移量和原始数据的十六进制和 ASCII 格式
        self.raw_text.delete("1.0", tk.END)
        self.offset_text.configure(state="normal")
        self.offset_text.delete("1.0", tk.END)

        hex_lines = self.format_hex_and_ascii(raw_bytes)

        # 插入 offset 和 raw data
        for offset, hex_line in hex_lines:
            self.offset_text.insert(tk.END, f"{offset}\n")
            self.raw_text.insert(tk.END, f"{hex_line}\n")

        self.offset_text.configure(state="disabled")

        # 显示解析后的数据包内容
        self.parsed_text.delete("1.0", tk.END)
        self.parsed_text.insert(tk.END, self.get_parsed_packet_info(packet))

    def format_hex_and_ascii(self, data):
        """
        将数据格式化为 Wireshark 风格的十六进制和 ASCII 显示。
        每行 16 字节，左侧显示偏移量，中间显示十六进制数据，右侧显示 ASCII 字符。
        """
        hex_lines = []
        for i in range(0, len(data), 16):
            # 偏移量，如 0000, 0010, 0020...
            offset = f"{i:04x}"

            # 提取 16 字节数据，并转换为十六进制显示
            chunk = data[i:i + 16]
            hex_bytes = [f"{byte:02x}" for byte in chunk]

            # 在第八个字节后插入两个空格
            if len(hex_bytes) > 8:
                hex_bytes.insert(8, "  ")  # 插入两个空格

            # 连接十六进制字符串
            hex_bytes_str = " ".join(hex_bytes)

            # 如果不足 16 字节，填充空格确保对齐
            hex_padding = "   " * (16 - len(chunk))
            formatted_hex = f"{hex_bytes_str}{hex_padding}"

            # ASCII 显示，不可见字符显示为 '.'
            ascii_repr = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)

            # 最终格式：十六进制部分 + 3 个空格 + ASCII 部分
            hex_line = f"{formatted_hex}             {ascii_repr}"
            hex_lines.append((offset, hex_line))

        return hex_lines

    def get_parsed_packet_info(self, packet):
        """
        返回格式化后的数据包信息，其中 IP 和 MAC 地址转换为可读格式。
        """
        # 保存格式化后的输出
        output = []

        # Ethernet 层
        if packet.haslayer(scapy.Ether):
            ether = packet.getlayer(scapy.Ether)
            output.append(f"### [ Ethernet ] ###")
            output.append(f"dst      = {ether.dst}")
            output.append(f"src      = {ether.src}")
            output.append(f"type     = {ether.type}")

        # IP 层
        if packet.haslayer(IP):
            ip = packet.getlayer(IP)
            output.append(f"### [ IP ] ###")
            output.append(f"version  = {ip.version}")
            output.append(f"ihl      = {ip.ihl}")
            output.append(f"tos      = {ip.tos}")
            output.append(f"len      = {ip.len}")
            output.append(f"id       = {ip.id}")
            output.append(f"flags    = {ip.flags}")
            output.append(f"frag     = {ip.frag}")
            output.append(f"ttl      = {ip.ttl}")
            output.append(f"proto    = {ip.proto}")
            output.append(f"chksum   = {ip.chksum}")
            output.append(f"src      = {ip.src}")
            output.append(f"dst      = {ip.dst}")

        # # IPv6 层
        # if packet.haslayer(IPv6):
        #     ipv6 = packet.getlayer(IPv6)
        #     output.append(f"### [ IPv6 ] ###")
        #     output.append(f"version  = {ipv6.version}")
        #     output.append(f"tc       = {ipv6.tc}")
        #     output.append(f"fl       = {ipv6.fl}")
        #     output.append(f"plen     = {ipv6.plen}")
        #     output.append(f"nh       = {ipv6.nh}")
        #     output.append(f"hlim     = {ipv6.hlim}")
        #     output.append(f"src      = {ipv6.src}")
        #     output.append(f"dst      = {ipv6.dst}")

        # TCP 层
        if packet.haslayer(TCP):
            tcp = packet.getlayer(TCP)
            output.append(f"### [ TCP ] ###")
            output.append(f"sport    = {tcp.sport}")
            output.append(f"dport    = {tcp.dport}")
            output.append(f"seq      = {tcp.seq}")
            output.append(f"ack      = {tcp.ack}")
            output.append(f"dataofs  = {tcp.dataofs}")
            output.append(f"reserved = {tcp.reserved}")
            output.append(f"flags    = {tcp.flags}")
            output.append(f"window   = {tcp.window}")
            output.append(f"chksum   = {tcp.chksum}")
            output.append(f"urgptr   = {tcp.urgptr}")

        # UDP 层
        if packet.haslayer(UDP):
            udp = packet.getlayer(UDP)
            output.append(f"### [ UDP ] ###")
            output.append(f"sport    = {udp.sport}")
            output.append(f"dport    = {udp.dport}")
            output.append(f"len      = {udp.len}")
            output.append(f"chksum   = {udp.chksum}")

        # DNS 层
        if packet.haslayer(DNS):
            dns = packet.getlayer(DNS)
            output.append(f"### [ DNS ] ###")
            output.append(f"id       = {dns.id}")
            output.append(f"qr       = {'Query' if dns.qr == 0 else 'Response'}")
            output.append(f"opcode   = {dns.opcode}")
            output.append(f"rcode    = {dns.rcode}")
            output.append(f"qdcount  = {dns.qdcount}")
            output.append(f"ancount  = {dns.ancount}")
            output.append(f"nscount  = {dns.nscount}")
            output.append(f"arcount  = {dns.arcount}")

            # Query Section
            if dns.qr == 0 and dns.qdcount > 0:
                if hasattr(dns, 'qd') and isinstance(dns.qd, DNSQR):
                    output.append("### [ DNS Query Section ] ###")
                    for i in range(dns.qdcount):
                        query = dns.qd if dns.qdcount == 1 else dns.qd[i]
                        if query:
                            output.append(
                                f"QName    = {query.qname.decode() if hasattr(query.qname, 'decode') else query.qname}")
                            output.append(f"QType    = {query.qtype}")
                            output.append(f"QClass   = {query.qclass}")

            # Answer Section
            if dns.qr == 1 and dns.ancount > 0:
                if hasattr(dns, 'an') and isinstance(dns.an, DNSRR):
                    output.append("### [ DNS Answer Section ] ###")
                    for i in range(dns.ancount):
                        answer = dns.an if dns.ancount == 1 else dns.an[i]
                        if answer:
                            output.append(
                                f"Name     = {answer.rrname.decode() if hasattr(answer.rrname, 'decode') else answer.rrname}")
                            output.append(f"Type     = {answer.type}")
                            output.append(f"Class    = {answer.rclass}")
                            output.append(f"TTL      = {answer.ttl}")
                            output.append(f"RData    = {answer.rdata}")

        # ICMPv6 层
        if packet.haslayer(ICMPv6EchoRequest):
            icmpv6 = packet.getlayer(ICMPv6EchoRequest)
            output.append(f"### [ ICMPv6 Echo Request ] ###")
            output.append(f"type     = {icmpv6.type}")
            output.append(f"code     = {icmpv6.code}")
            output.append(f"id       = {icmpv6.id}")
            output.append(f"seq      = {icmpv6.seq}")

        elif packet.haslayer(ICMPv6EchoReply):
            icmpv6 = packet.getlayer(ICMPv6EchoReply)
            output.append(f"### [ ICMPv6 Echo Reply ] ###")
            output.append(f"type     = {icmpv6.type}")
            output.append(f"code     = {icmpv6.code}")
            output.append(f"id       = {icmpv6.id}")
            output.append(f"seq      = {icmpv6.seq}")

        elif packet.haslayer(ICMPv6ND_NS):
            icmpv6 = packet.getlayer(ICMPv6ND_NS)
            output.append(f"### [ ICMPv6 Neighbor Solicitation ] ###")
            output.append(f"type     = {icmpv6.type}")
            output.append(f"code     = {icmpv6.code}")
            output.append(f"target   = {icmpv6.tgt}")

        elif packet.haslayer(ICMPv6ND_NA):
            icmpv6 = packet.getlayer(ICMPv6ND_NA)
            output.append(f"### [ ICMPv6 Neighbor Advertisement ] ###")
            output.append(f"type     = {icmpv6.type}")
            output.append(f"code     = {icmpv6.code}")
            output.append(f"target   = {icmpv6.tgt}")
            output.append(f"flags    = {icmpv6.flags}")

        elif packet.haslayer(ICMPv6ND_RA):
            icmpv6 = packet.getlayer(ICMPv6ND_RA)
            output.append(f"### [ ICMPv6 Router Advertisement ] ###")
            output.append(f"type     = {icmpv6.type}")
            output.append(f"code     = {icmpv6.code}")
            output.append(f"router lifetime = {icmpv6.routerlifetime}")
            output.append(f"reachable time  = {icmpv6.reachabletime}")
            output.append(f"retrans timer   = {icmpv6.retranstimer}")

        # HTTP 层
        if packet.haslayer(HTTPRequest):
            http = packet.getlayer(HTTPRequest)
            output.append(f"### [ HTTP Request ] ###")
            output.append(f"Method   = {http.Method.decode()}")
            output.append(f"Host     = {http.Host.decode()}")
            output.append(f"Path     = {http.Path.decode()}")
            output.append(f"User-Agent = {http.User_Agent.decode()}")

        elif packet.haslayer(HTTPResponse):
            http = packet.getlayer(HTTPResponse)
            output.append(f"### [ HTTP Response ] ###")
            output.append(f"Status Code = {http.Status_Code.decode()}")
            output.append(f"Reason-Phrase = {http.Reason_Phrase.decode()}")

        # 如果没有解析出的内容，添加默认信息
        if not output:
            output.append("No Parsed Information Available.")

        return "\n".join(output)

    def show_context_menu(self, event):
        # 创建右键菜单
        context_menu = tk.Menu(self.packet_tree, tearoff=0)
        context_menu.add_command(label="Analyze", command=self.analyze_stream)
        context_menu.post(event.x_root, event.y_root)

    def analyze_stream(self):
        selected_item = self.packet_tree.selection()
        if not selected_item:
            return

        item_index = int(self.packet_tree.item(selected_item)['values'][0]) - 1
        selected_packet = self.captured_packets[item_index]

        # Determine protocol and session_info for IPv4 or IPv6
        if TCP in selected_packet:
            protocol = "TCP"
            if IP in selected_packet:
                session_info = (
                    selected_packet[IP].src,
                    selected_packet[IP].dst,
                    selected_packet[TCP].sport,
                    selected_packet[TCP].dport,
                )
            elif IPv6 in selected_packet:
                session_info = (
                    selected_packet[IPv6].src,
                    selected_packet[IPv6].dst,
                    selected_packet[TCP].sport,
                    selected_packet[TCP].dport,
                )
            else:
                tk.messagebox.showerror("Error", "This packet does not have IP or IPv6 layers.")
                return
        elif UDP in selected_packet:
            protocol = "UDP"
            if IP in selected_packet:
                session_info = (
                    selected_packet[IP].src,
                    selected_packet[IP].dst,
                    selected_packet[UDP].sport,
                    selected_packet[UDP].dport,
                )
            elif IPv6 in selected_packet:
                session_info = (
                    selected_packet[IPv6].src,
                    selected_packet[IPv6].dst,
                    selected_packet[UDP].sport,
                    selected_packet[UDP].dport,
                )
        else:
            tk.messagebox.showerror("Error", "This protocol is not supported for analysis.")
            return

        # Create stream window
        self.create_stream_window(session_info, protocol)

        # Filter packets based on selected session_info
        self.display_filtered_packets(session_info)

    def display_filtered_packets(self, session_info):
        """
        根据给定的 session_info (源IP，目的IP，源端口，目的端口) 筛选数据包，并更新 Treeview 显示。
        """
        # Clear current Treeview display
        self.packet_tree.delete(*self.packet_tree.get_children())

        # Unpack session_info for easy comparison
        src_ip, dst_ip, src_port, dst_port = session_info

        # Filter packets that match the session_info in both directions
        for packet_data in self.displayed_packets:
            packet_count, timestamp, source, destination, ip_n, protocol_name, length, info, packet = packet_data

            # Check if packet matches the selected session_info for TCP/UDP packets in either direction
            if IP in packet or IPv6 in packet:
                # Handle IPv4 case
                if IP in packet:
                    packet_src_ip, packet_dst_ip = packet[IP].src, packet[IP].dst
                    packet_src_port = packet[TCP].sport if packet.haslayer(TCP) else (
                        packet[UDP].sport if packet.haslayer(UDP) else None)
                    packet_dst_port = packet[TCP].dport if packet.haslayer(TCP) else (
                        packet[UDP].dport if packet.haslayer(UDP) else None)

                # Handle IPv6 case
                elif IPv6 in packet:
                    packet_src_ip, packet_dst_ip = packet[IPv6].src, packet[IPv6].dst
                    packet_src_port = packet[TCP].sport if packet.haslayer(TCP) else (
                        packet[UDP].sport if packet.haslayer(UDP) else None)
                    packet_dst_port = packet[TCP].dport if packet.haslayer(TCP) else (
                        packet[UDP].dport if packet.haslayer(UDP) else None)

                # Ensure that both ports are not None (i.e., the packet has TCP or UDP layer)
                if packet_src_port is not None and packet_dst_port is not None:
                    # Check if packet matches the session in either direction
                    if (
                            packet_src_ip == src_ip and packet_dst_ip == dst_ip and packet_src_port == src_port and packet_dst_port == dst_port) or \
                            (
                                    packet_src_ip == dst_ip and packet_dst_ip == src_ip and packet_src_port == dst_port and packet_dst_port == src_port):
                        # Insert the filtered packet into the Treeview
                        self.packet_tree.insert("", "end",
                                                values=(
                                                packet_count, timestamp, source, destination, ip_n, protocol_name, length,
                                                info))

    def create_stream_window(self, session_info, protocol):
        stream_window = Toplevel(self.root)
        stream_window.title(f"{protocol} Stream Analysis")

        main_frame = tk.Frame(stream_window)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Text box for displaying stream data with colors
        stream_text = tk.Text(main_frame, wrap="word")
        stream_text.pack(fill=tk.BOTH, expand=True)

        # 设置标签颜色
        stream_text.tag_configure("src_to_dst", foreground="red")
        stream_text.tag_configure("dst_to_src", foreground="blue")

        # 筛选并显示符合会话的包
        self.display_stream_data(stream_text, session_info, protocol)

    def display_stream_data(self, stream_text, session_info, protocol):
        stream_text.delete("1.0", tk.END)

        for packet in self.captured_packets:
            if TCP in packet:
                # Check for IPv4 session
                if IP in packet and (
                        (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport) == session_info or
                        (packet[IP].dst, packet[IP].src, packet[TCP].dport, packet[TCP].sport) == session_info
                ):
                    direction = "src_to_dst" if (packet[IP].src, packet[IP].dst, packet[TCP].sport,
                                                 packet[TCP].dport) == session_info else "dst_to_src"
                    label = f"{packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}"

                # Check for IPv6 session
                elif IPv6 in packet and (
                        (packet[IPv6].src, packet[IPv6].dst, packet[TCP].sport, packet[TCP].dport) == session_info or
                        (packet[IPv6].dst, packet[IPv6].src, packet[TCP].dport, packet[TCP].sport) == session_info
                ):
                    direction = "src_to_dst" if (packet[IPv6].src, packet[IPv6].dst, packet[TCP].sport,
                                                 packet[TCP].dport) == session_info else "dst_to_src"
                    label = f"{packet[IPv6].src}:{packet[TCP].sport} -> {packet[IPv6].dst}:{packet[TCP].dport}"
                else:
                    continue  # Skip packets that don't match the session

                # Attempt to decode TCP payload
                payload = bytes(packet[TCP].payload)
                try:
                    decoded_payload = payload.decode('utf-8')
                except UnicodeDecodeError:
                    # Filter non-printable characters and replace with '.'
                    decoded_payload = ''.join((char if char in string.printable else '.') for char in
                                              payload.decode('utf-8', errors='ignore'))

                # Insert the packet data into the text widget with direction-based color
                packet_data = f"{label}\n{decoded_payload}\n\n"
                stream_text.insert(tk.END, packet_data, direction)

    def apply_filter(self, event):
        # 清空当前的包树
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.captured_packets.clear()

        # 先获取所有的过滤条件
        ip_filter_value = self.filter_IP.get()
        protocol_filter_value = self.filter_protocol.get()

        for packet_data in self.displayed_packets:
            packet_count, timestamp, source, destination, ip_n, protocol_name, length, info, packet = packet_data

            # 初始条件，检查是否符合 IP 过滤
            ip_matches = (ip_filter_value == "All" or ip_n == ip_filter_value)

            # 如果 IP 过滤符合，再检查协议过滤
            if ip_matches:
                # 根据协议过滤
                if protocol_filter_value == "All" or protocol_name == protocol_filter_value:
                    self.packet_tree.insert("", "end", values=(
                        packet_count, timestamp, source, destination, ip_n, protocol_name, length, info))
                    self.captured_packets.append(packet)



if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSniffer(root)
    root.mainloop()
