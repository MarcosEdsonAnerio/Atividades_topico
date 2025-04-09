#!/usr/bin/env python3
"""
Advanced Port Scanner - Versão Aprimorada
Disciplina: Tópicos Especiais II - ADS 2025/1
Turma: 20251.6.0206.238.1N
"""

import subprocess
import socket
import threading
import csv
import json
from datetime import datetime
from tkinter import *
from tkinter import messagebox, filedialog, ttk
from scapy.all import IP, TCP, UDP, ICMP, sr1, sr, conf
import netifaces

# Configuração inicial
conf.verb = 0  # Remove output verboso do Scapy
VERSION = "2.0"
AUTHOR = "Seu Nome"
REPO_URL = "https://github.com/seuusuario/advanced-port-scanner"

class AdvancedPortScanner:
    """Classe principal do scanner de portas avançado"""
    
    def __init__(self):
        self.target_ips = []
        self.results = {}
        self.scan_history = []
    
    def validate_ip(self, ip):
        """Valida se um endereço IP é válido"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def run_nmap_scan(self, target, scan_type="SYN", ports=None, timing=None):
        """
        Executa varredura do Nmap com opções avançadas
        
        Args:
            target (str): IP ou range a ser escaneado
            scan_type (str): Tipo de scan (SYN, UDP, Version, OS, Advanced)
            ports (str): Range de portas (ex: "1-1000")
            timing (int): Agressividade do scan (0-5)
        
        Returns:
            str: Resultado do scan
        """
        command = ["nmap", "-n", target]
        
        # Adiciona tipo de scan
        scan_options = {
            "SYN": "-sS",
            "UDP": "-sU",
            "Version": "-sV",
            "OS": "-O",
            "Advanced": "-A"
        }
        command.append(scan_options.get(scan_type, "-sS"))
        
        # Adiciona range de portas se especificado
        if ports:
            command.extend(["-p", ports])
        
        # Adiciona timing se especificado
        if timing is not None and 0 <= timing <= 5:
            command.extend(["-T", str(timing)])
        
        # Executa o comando
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Erro ao executar Nmap: {str(e)}"
    
    def scan_tcp_port(self, ip, port, timeout=1):
        """Verifica o status de uma porta TCP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()
            
            if result == 0:
                return "open"
            elif result == 11:  # Linux timeout error
                return "filtered"
            else:
                return "closed"
        except socket.error:
            return "error"
    
    def scan_udp_port(self, ip, port, timeout=1):
        """Verifica o status de uma porta UDP"""
        try:
            # Envia pacote UDP vazio
            pkt = IP(dst=ip)/UDP(dport=port)
            response = sr1(pkt, timeout=timeout, verbose=0)
            
            if response is None:
                return "open|filtered"
            elif response.haslayer(UDP):
                return "open"
            elif response.haslayer(ICMP):
                if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1, 2, 9, 10, 13]:
                    return "closed"
            return "filtered"
        except Exception:
            return "error"
    
    def ping_host(self, ip, count=3):
        """Verifica se um host está respondendo a ping"""
        try:
            responses = []
            for _ in range(count):
                response = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
                if response:
                    responses.append(response.time * 1000)  # ms
            
            if responses:
                avg = sum(responses) / len(responses)
                return f"Host {ip} está ativo. Tempo médio: {avg:.2f}ms"
            return f"Host {ip} não respondeu ao ping"
        except Exception as e:
            return f"Erro ao pingar {ip}: {str(e)}"
    
    def export_results(self, format_type="txt", filename=None):
        """
        Exporta os resultados para um arquivo
        
        Args:
            format_type (str): Formato de exportação (txt, csv, json)
            filename (str): Nome do arquivo de saída
        
        Returns:
            bool: True se exportação foi bem sucedida
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{timestamp}.{format_type}"
        
        try:
            if format_type == "txt":
                with open(filename, "w") as f:
                    for ip, result in self.results.items():
                        f.write(f"=== Resultados para {ip} ===\n")
                        f.write(result + "\n\n")
            
            elif format_type == "csv":
                with open(filename, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["IP", "Porta", "Protocolo", "Status"])
                    for ip, result in self.results.items():
                        # Parse básico dos resultados para CSV
                        # (implementação mais sofisticada seria necessária)
                        writer.writerow([ip, "Várias", "TCP/UDP", "Ver relatório completo"])
            
            elif format_type == "json":
                with open(filename, "w") as f:
                    json.dump(self.results, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Erro ao exportar resultados: {str(e)}")
            return False

class ScannerApp:
    """Interface gráfica do scanner de portas"""
    
    def __init__(self, root):
        self.root = root
        self.root.title(f"Advanced Port Scanner v{VERSION}")
        self.root.geometry("800x700")
        self.port_scanner = AdvancedPortScanner()
        self.create_ui()
        self.setup_menu()
    
    def create_ui(self):
        """Cria a interface do usuário"""
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=BOTH, expand=True)
        
        # Frame de IPs
        ip_frame = ttk.LabelFrame(main_frame, text="IPs de Destino", padding="10")
        ip_frame.pack(fill=X, pady=5)
        
        self.ip_input = ttk.Entry(ip_frame, width=40)
        self.ip_input.grid(row=0, column=0, padx=5)
        self.ip_input.insert(0, "10.49.6.132")
        
        ttk.Button(ip_frame, text="Adicionar IP", command=self.add_ip).grid(row=0, column=1, padx=5)
        ttk.Button(ip_frame, text="Limpar Lista", command=self.clear_ips).grid(row=0, column=2, padx=5)
        
        self.ip_listbox = Listbox(ip_frame, height=4, width=50, selectmode=MULTIPLE)
        self.ip_listbox.grid(row=1, column=0, columnspan=3, pady=5)
        
        # Frame de opções de scan
        options_frame = ttk.LabelFrame(main_frame, text="Opções de Varredura", padding="10")
        options_frame.pack(fill=X, pady=5)
        
        # Tipo de scan
        ttk.Label(options_frame, text="Tipo de Scan:").grid(row=0, column=0, sticky=W)
        self.scan_type = StringVar(value="SYN")
        
        scan_types = [
            ("SYN Scan", "SYN"),
            ("UDP Scan", "UDP"),
            ("Detecção de Versão", "Version"),
            ("Detecção de OS", "OS"),
            ("Scan Avançado", "Advanced")
        ]
        
        for i, (text, val) in enumerate(scan_types):
            ttk.Radiobutton(options_frame, text=text, variable=self.scan_type, value=val).grid(
                row=1, column=i, padx=5, sticky=W)
        
        # Opções avançadas
        ttk.Label(options_frame, text="Portas (ex: 80,443 ou 1-1000):").grid(row=2, column=0, sticky=W)
        self.port_range = ttk.Entry(options_frame, width=20)
        self.port_range.grid(row=2, column=1, sticky=W)
        
        ttk.Label(options_frame, text="Timing (0-5):").grid(row=2, column=2, sticky=W)
        self.timing = ttk.Combobox(options_frame, values=[0,1,2,3,4,5], width=3)
        self.timing.current(3)
        self.timing.grid(row=2, column=3, sticky=W)
        
        # Botões de ação
        button_frame = ttk.Frame(options_frame)
        button_frame.grid(row=3, column=0, columnspan=5, pady=5)
        
        ttk.Button(button_frame, text="Iniciar Varredura", command=self.start_scan).pack(side=LEFT, padx=5)
        ttk.Button(button_frame, text="Pingar Hosts", command=self.ping_hosts).pack(side=LEFT, padx=5)
        ttk.Button(button_frame, text="Verificar Portas", command=self.check_ports).pack(side=LEFT, padx=5)
        
        # Área de resultados
        result_frame = ttk.LabelFrame(main_frame, text="Resultados", padding="10")
        result_frame.pack(fill=BOTH, expand=True)
        
        self.result_text = Text(result_frame, wrap=WORD)
        self.result_text.pack(fill=BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(self.result_text)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.result_text.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.result_text.yview)
        
        # Barra de status
        self.status_var = StringVar(value="Pronto")
        ttk.Label(main_frame, textvariable=self.status_var, relief=SUNKEN).pack(fill=X, pady=5)
    
    def setup_menu(self):
        """Configura o menu superior"""
        menubar = Menu(self.root)
        
        # Menu Arquivo
        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exportar como TXT", command=lambda: self.export_results("txt"))
        file_menu.add_command(label="Exportar como CSV", command=lambda: self.export_results("csv"))
        file_menu.add_command(label="Exportar como JSON", command=lambda: self.export_results("json"))
        file_menu.add_separator()
        file_menu.add_command(label="Sair", command=self.root.quit)
        menubar.add_cascade(label="Arquivo", menu=file_menu)
        
        # Menu Ajuda
        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label="Sobre", command=self.show_about)
        help_menu.add_command(label="Documentação", command=self.show_docs)
        menubar.add_cascade(label="Ajuda", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def add_ip(self):
        """Adiciona um IP à lista de varredura"""
        ip = self.ip_input.get().strip()
        if ip and self.port_scanner.validate_ip(ip):
            self.ip_listbox.insert(END, ip)
            self.ip_input.delete(0, END)
        else:
            messagebox.showerror("Erro", "Por favor, insira um IP válido!")
    
    def clear_ips(self):
        """Limpa a lista de IPs"""
        self.ip_listbox.delete(0, END)
    
    def start_scan(self):
        """Inicia a varredura de portas"""
        ips = [self.ip_listbox.get(i) for i in range(self.ip_listbox.size())]
        if not ips:
            messagebox.showerror("Erro", "Adicione pelo menos um IP para escanear!")
            return
        
        scan_type = self.scan_type.get()
        ports = self.port_range.get().strip() or None
        timing = int(self.timing.get()) if self.timing.get() else None
        
        self.result_text.delete(1.0, END)
        self.result_text.insert(END, f"Iniciando varredura {scan_type}...\n")
        self.status_var.set(f"Escaneando {len(ips)} IP(s)...")
        
        def scan():
            for ip in ips:
                self.result_text.insert(END, f"\n=== Escaneando {ip} ===\n")
                result = self.port_scanner.run_nmap_scan(ip, scan_type, ports, timing)
                self.port_scanner.results[ip] = result
                self.result_text.insert(END, result + "\n")
                self.result_text.see(END)
                self.root.update()
            
            self.status_var.set("Varredura concluída!")
            messagebox.showinfo("Concluído", "Varredura finalizada com sucesso!")
        
        threading.Thread(target=scan, daemon=True).start()
    
    def ping_hosts(self):
        """Executa ping nos hosts selecionados"""
        ips = [self.ip_listbox.get(i) for i in range(self.ip_listbox.size())]
        if not ips:
            messagebox.showerror("Erro", "Adicione pelo menos um IP para pingar!")
            return
        
        self.result_text.delete(1.0, END)
        self.result_text.insert(END, "Iniciando ping nos hosts...\n")
        self.status_var.set(f"Pingando {len(ips)} host(s)...")
        
        def ping():
            for ip in ips:
                result = self.port_scanner.ping_host(ip)
                self.result_text.insert(END, f"{result}\n")
                self.result_text.see(END)
                self.root.update()
            
            self.status_var.set("Ping concluído!")
        
        threading.Thread(target=ping, daemon=True).start()
    
    def check_ports(self):
        """Verifica portas específicas nos hosts"""
        ips = [self.ip_listbox.get(i) for i in range(self.ip_listbox.size())]
        if not ips:
            messagebox.showerror("Erro", "Adicione pelo menos um IP!")
            return
        
        ports = self.port_range.get().strip()
        if not ports:
            messagebox.showerror("Erro", "Informe as portas a verificar!")
            return
        
        self.result_text.delete(1.0, END)
        self.result_text.insert(END, f"Verificando portas {ports}...\n")
        self.status_var.set(f"Verificando portas em {len(ips)} host(s)...")
        
        def check():
            for ip in ips:
                self.result_text.insert(END, f"\n=== {ip} ===\n")
                
                # Verifica portas TCP
                self.result_text.insert(END, "Portas TCP:\n")
                for port in self.parse_ports(ports):
                    status = self.port_scanner.scan_tcp_port(ip, port)
                    self.result_text.insert(END, f"  Porta {port}: {status}\n")
                    self.result_text.see(END)
                    self.root.update()
                
                # Verifica portas UDP (apenas para portas altas)
                self.result_text.insert(END, "\nPortas UDP:\n")
                for port in self.parse_ports(ports):
                    if port > 1024:  # Portas UDP baixas geralmente não respondem
                        status = self.port_scanner.scan_udp_port(ip, port)
                        self.result_text.insert(END, f"  Porta {port}: {status}\n")
                        self.result_text.see(END)
                        self.root.update()
            
            self.status_var.set("Verificação de portas concluída!")
        
        threading.Thread(target=check, daemon=True).start()
    
    def parse_ports(self, port_str):
        """Converte string de portas para lista de números"""
        ports = []
        for part in port_str.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return ports
    
    def export_results(self, format_type):
        """Exporta os resultados para um arquivo"""
        if not self.port_scanner.results:
            messagebox.showerror("Erro", "Nenhum resultado para exportar!")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=f".{format_type}",
            filetypes=[(f"{format_type.upper()} files", f"*.{format_type}")],
            title="Salvar resultados como"
        )
        
        if filename:
            success = self.port_scanner.export_results(format_type, filename)
            if success:
                messagebox.showinfo("Sucesso", f"Resultados exportados para {filename}")
            else:
                messagebox.showerror("Erro", "Falha ao exportar resultados!")
    
    def show_about(self):
        """Mostra a janela 'Sobre'"""
        about_text = f"""
Advanced Port Scanner v{VERSION}

Desenvolvido por: {AUTHOR}
Repositório: {REPO_URL}

Disciplina: Tópicos Especiais II
Turma: 20251.6.0206.238.1N
        """
        messagebox.showinfo("Sobre", about_text.strip())
    
    def show_docs(self):
        """Mostra a documentação básica"""
        docs_text = """
INSTRUÇÕES DE USO:

1. Adicione IPs para escanear no campo 'IPs de Destino'
2. Selecione o tipo de varredura:
   - SYN Scan: Varredura TCP rápida (padrão)
   - UDP Scan: Varredura de portas UDP
   - Detecção de Versão: Identifica versões de serviços
   - Detecção de OS: Tenta identificar o sistema operacional
   - Scan Avançado: Combina várias técnicas

3. Opções:
   - Especifique portas (ex: 80,443 ou 1-1000)
   - Ajuste o timing (0-5) para velocidade do scan

4. Ações:
   - Iniciar Varredura: Executa o scan selecionado
   - Pingar Hosts: Verifica se os hosts estão ativos
   - Verificar Portas: Testa portas específicas

5. Exporte os resultados em TXT, CSV ou JSON
        """
        text_window = Toplevel(self.root)
        text_window.title("Documentação")
        
        text = Text(text_window, wrap=WORD, width=80, height=20)
        text.pack(fill=BOTH, expand=True)
        text.insert(END, docs_text.strip())
        text.config(state=DISABLED)
        
        ttk.Button(text_window, text="Fechar", command=text_window.destroy).pack(pady=5)

if __name__ == "__main__":
    root = Tk()
    app = ScannerApp(root)
    root.mainloop()