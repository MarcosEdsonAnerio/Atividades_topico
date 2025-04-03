#!/usr/bin/env python3
import subprocess
import socket
import threading
from tkinter import *
from tkinter import messagebox
from scapy.all import IP, TCP, ICMP, sr1, sr

class AdvancedPortScanner:
    def __init__(self):
        self.target_ips = []
        self.results = {}

    def run_nmap_scan(self, target, scan_type):
        """Executa varredura do Nmap com base no tipo de scan"""
        command = ["nmap", "-n", target]  # Define a base do comando Nmap
        
        # Adiciona o tipo de scan específico
        if scan_type == "SYN":
            command += ["-sS"]
        elif scan_type == "UDP":
            command += ["-sU"]
        elif scan_type == "Version":
            command += ["-sV"]
        elif scan_type == "OS":
            command += ["-O"]
        elif scan_type == "Advanced":
            command += ["-A"]

        # Executa o comando Nmap e captura a saída
        result = subprocess.run(command, capture_output=True, text=True)
        return result.stdout

    def scan_ips(self, ips, scan_type):
        """Escaneia múltiplos IPs para o tipo de varredura fornecido"""
        all_results = {}
        for ip in ips:
            all_results[ip] = self.run_nmap_scan(ip, scan_type)
        return all_results
    
    def scan_tcp_port(self, ip, port):
        """Verifica se uma porta TCP está aberta, fechada ou filtrada"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                return "Aberta"
            else:
                return "Fechada"
        except socket.error:
            return "Filtrada"
    
    def scan_udp_port(self, ip, port):
        """Verifica se uma porta UDP está aberta ou filtrada"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.sendto(b"", (ip, port))
            s.recvfrom(1024)
            s.close()
            return "Aberta"
        except socket.timeout:
            return "Filtrada"
        except socket.error:
            return "Fechada"
    
    def ping_host(self, ip):
        """Faz ping em um host para verificar se está ativo"""
        try:
            response = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
            if response:
                return f"Host {ip} está ativo. Tempo: {response.time}ms"
            else:
                return f"Sem resposta de {ip}"
        except Exception as e:
            return f"Erro ao pingar {ip}: {str(e)}"

class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Port Scanner")
        self.root.geometry("700x800")
        self.port_scanner = AdvancedPortScanner()
        self.create_ui()

    def create_ui(self):
        """Criação dos elementos da interface gráfica"""
        # Frame de IPs
        ip_frame = LabelFrame(self.root, text="IPs de Destino", padx=10, pady=10)
        ip_frame.pack(fill=X, padx=10, pady=5)

        self.ip_input = Entry(ip_frame, width=40)
        self.ip_input.grid(row=0, column=0, padx=5)
        self.ip_input.insert(0, "192.168.1.1")

        self.add_ip_button = Button(ip_frame, text="Adicionar IP", command=self.add_ip)
        self.add_ip_button.grid(row=0, column=1, padx=5)

        self.ip_listbox = Listbox(ip_frame, height=4, width=50)
        self.ip_listbox.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        # Frame de opções de scan
        options_frame = LabelFrame(self.root, text="Opções de Varredura", padx=10, pady=10)
        options_frame.pack(fill=X, padx=10, pady=5)

        self.scan_type_var = StringVar()
        self.scan_type_var.set("SYN")

        self.syn_radio = Radiobutton(options_frame, text="SYN Scan", variable=self.scan_type_var, value="SYN")
        self.syn_radio.grid(row=0, column=0)
        self.udp_radio = Radiobutton(options_frame, text="UDP Scan", variable=self.scan_type_var, value="UDP")
        self.udp_radio.grid(row=0, column=1)
        self.version_radio = Radiobutton(options_frame, text="Detecção de Versão", variable=self.scan_type_var, value="Version")
        self.version_radio.grid(row=0, column=2)
        self.os_radio = Radiobutton(options_frame, text="Detecção de Sistema", variable=self.scan_type_var, value="OS")
        self.os_radio.grid(row=0, column=3)
        self.advanced_radio = Radiobutton(options_frame, text="Scan Avançado", variable=self.scan_type_var, value="Advanced")
        self.advanced_radio.grid(row=0, column=4)

        self.scan_button = Button(options_frame, text="Iniciar Varredura", command=self.start_scan)
        self.scan_button.grid(row=1, column=0, columnspan=5, pady=5)

        # Adicionar verificação de ping
        self.ping_button = Button(options_frame, text="Pingar Hosts", command=self.ping_hosts)
        self.ping_button.grid(row=2, column=0, columnspan=5, pady=5)

        # Adicionar campo para as portas
        self.port_input_label = Label(options_frame, text="Portas (ex: 22,80,443):")
        self.port_input_label.grid(row=3, column=0, padx=5, pady=5)

        self.port_input = Entry(options_frame, width=40)
        self.port_input.grid(row=3, column=1, padx=5, pady=5)

        self.port_check_button = Button(options_frame, text="Verificar Portas", command=self.check_ports)
        self.port_check_button.grid(row=3, column=2, padx=5, pady=5)

        # Área de Resultados
        self.result_area = Text(self.root, height=20, width=80)
        self.result_area.pack(padx=10, pady=10)

    def add_ip(self):
        """Adiciona um IP à lista de IPs"""
        ip = self.ip_input.get()
        if ip:
            self.ip_listbox.insert(END, ip)
        else:
            messagebox.showerror("Erro", "Digite um IP válido!")

    def start_scan(self):
        """Inicia a varredura de portas avançada"""
        ips = [self.ip_listbox.get(i) for i in range(self.ip_listbox.size())]
        scan_type = self.scan_type_var.get()

        if not ips:
            messagebox.showerror("Erro", "Adicione IPs para escanear!")
            return

        self.result_area.delete(1.0, END)
        self.result_area.insert(END, f"Iniciando varredura do tipo {scan_type} para {len(ips)} IPs...\n")

        def scan():
            results = self.port_scanner.scan_ips(ips, scan_type)
            for ip, result in results.items():
                self.result_area.insert(END, f"\nResultados para {ip}:\n")
                self.result_area.insert(END, result)
                self.result_area.insert(END, "-"*50 + "\n")
            self.result_area.insert(END, "\nVarredura concluída!")

        threading.Thread(target=scan, daemon=True).start()

    def ping_hosts(self):
        """Faz ping em todos os IPs da lista"""
        ips = [self.ip_listbox.get(i) for i in range(self.ip_listbox.size())]
        if not ips:
            messagebox.showerror("Erro", "Adicione IPs para pingar!")
            return
        
        self.result_area.delete(1.0, END)
        self.result_area.insert(END, "Iniciando ping nos IPs...\n")

        def ping():
            for ip in ips:
                result = self.port_scanner.ping_host(ip)
                self.result_area.insert(END, f"{result}\n")

        threading.Thread(target=ping, daemon=True).start()

    def check_ports(self):
        """Verifica as portas TCP e UDP fornecidas pelo usuário"""
        ips = [self.ip_listbox.get(i) for i in range(self.ip_listbox.size())]
        if not ips:
            messagebox.showerror("Erro", "Adicione IPs para verificar as portas!")
            return

        ports_input = self.port_input.get()
        if not ports_input:
            messagebox.showerror("Erro", "Digite as portas que deseja verificar!")
            return

        try:
            ports = [int(port) for port in ports_input.split(",")]
        except ValueError:
            messagebox.showerror("Erro", "Portas inválidas! Use apenas números separados por vírgula.")
            return
        
        self.result_area.delete(1.0, END)
        self.result_area.insert(END, "Verificando portas...\n")

        def check_ports():
            for ip in ips:
                self.result_area.insert(END, f"\nVerificando {ip}:\n")
                
                for port in ports:
                    # Verificar portas TCP
                    if port <= 1023:  # Portas reservadas para TCP
                        status = self.port_scanner.scan_tcp_port(ip, port)
                        self.result_area.insert(END, f"Porta TCP {port}: {status}\n")
                    # Verificar portas UDP
                    status = self.port_scanner.scan_udp_port(ip, port)
                    self.result_area.insert(END, f"Porta UDP {port}: {status}\n")

        threading.Thread(target=check_ports, daemon=True).start()

if __name__ == "__main__":
    root = Tk()
    app = ScannerApp(root)
    root.mainloop()
