import zipfile
import time
import os
from threading import Thread, Lock, active_count
from queue import Queue
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import mmap

class AdvancedZIPPasswordCracker:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced ZIP Password Cracker")
        self.root.geometry("800x600")
        
        # Configurações
        self.max_threads = multiprocessing.cpu_count() * 2  # Aproveita melhor CPUs modernos
        self.batch_size = 1000  # Tamanho do lote de senhas para processar
        self.active_wordlists = 0
        
        # Variáveis de estado
        self.zip_file = ""
        self.wordlist_files = []
        self.found = False
        self.running = False
        self.tested = 0
        self.start_time = 0
        self.passwords_tested = 0
        self.passwords_total = 0
        
        # Otimizações
        self.password_cache = []
        self.cache_lock = Lock()
        self.executor = None
        
        # Interface
        self.create_widgets()
        
    def create_widgets(self):
        main_frame = tk.Frame(self.root, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configurações
        settings_frame = tk.LabelFrame(main_frame, text="Configurações", padx=10, pady=10)
        settings_frame.pack(fill=tk.X, pady=5)
        
        # Arquivo ZIP
        tk.Label(settings_frame, text="Arquivo ZIP:").grid(row=0, column=0, sticky=tk.W)
        self.zip_entry = tk.Entry(settings_frame, width=50)
        self.zip_entry.grid(row=0, column=1, sticky=tk.EW, padx=5)
        tk.Button(settings_frame, text="Procurar", command=self.browse_zip).grid(row=0, column=2, padx=5)
        
        # Wordlists
        tk.Label(settings_frame, text="Wordlists:").grid(row=1, column=0, sticky=tk.W)
        self.wordlist_listbox = tk.Listbox(settings_frame, height=4, selectmode=tk.EXTENDED)
        self.wordlist_listbox.grid(row=1, column=1, sticky=tk.EW, padx=5)
        scrollbar = tk.Scrollbar(settings_frame, orient=tk.VERTICAL)
        scrollbar.config(command=self.wordlist_listbox.yview)
        scrollbar.grid(row=1, column=3, sticky=tk.NS)
        self.wordlist_listbox.config(yscrollcommand=scrollbar.set)
        
        button_frame = tk.Frame(settings_frame)
        button_frame.grid(row=1, column=2, padx=5)
        tk.Button(button_frame, text="Adicionar", command=self.browse_wordlists).pack(fill=tk.X)
        tk.Button(button_frame, text="Remover", command=self.remove_wordlists).pack(fill=tk.X)
        
        # Configurações avançadas
        adv_frame = tk.Frame(settings_frame)
        adv_frame.grid(row=2, column=0, columnspan=3, sticky=tk.EW, pady=5)
        
        tk.Label(adv_frame, text="Threads:").pack(side=tk.LEFT)
        self.threads_var = tk.StringVar(value=str(self.max_threads))
        tk.Entry(adv_frame, textvariable=self.threads_var, width=5).pack(side=tk.LEFT, padx=5)
        
        tk.Label(adv_frame, text="Tamanho do lote:").pack(side=tk.LEFT, padx=(10,5))
        self.batch_var = tk.StringVar(value=str(self.batch_size))
        tk.Entry(adv_frame, textvariable=self.batch_var, width=8).pack(side=tk.LEFT)
        
        # Controles
        control_frame = tk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=10)
        
        self.start_button = tk.Button(control_frame, text="Iniciar", command=self.start_cracking, 
                                    bg="#4CAF50", fg="white", font=('Arial', 10, 'bold'))
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = tk.Button(control_frame, text="Parar", command=self.stop_cracking, 
                                   state=tk.DISABLED, bg="#f44336", fg="white", font=('Arial', 10, 'bold'))
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Estatísticas
        stats_frame = tk.Frame(main_frame)
        stats_frame.pack(fill=tk.X, pady=5)
        
        self.stats_var = tk.StringVar(value="Pronto para começar")
        tk.Label(stats_frame, textvariable=self.stats_var, anchor=tk.W).pack(fill=tk.X)
        
        self.speed_var = tk.StringVar(value="Velocidade: 0 senhas/seg")
        tk.Label(stats_frame, textvariable=self.speed_var, anchor=tk.W).pack(fill=tk.X)
        
        self.progress = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, pady=5)
        
        # Log
        tk.Label(main_frame, text="Log de Atividade:").pack(anchor=tk.W)
        self.log_text = scrolledtext.ScrolledText(main_frame, height=12, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Configurar colunas para expansão
        settings_frame.columnconfigure(1, weight=1)
        
    def browse_zip(self):
        self.zip_file = filedialog.askopenfilename(
            title="Selecione o arquivo ZIP",
            filetypes=(("Arquivos ZIP", "*.zip"), ("Todos os arquivos", "*.*"))
        )
        if self.zip_file:
            self.zip_entry.delete(0, tk.END)
            self.zip_entry.insert(0, self.zip_file)
    
    def browse_wordlists(self):
        initial_dir = "WordLists" if os.path.exists("WordLists") else os.path.expanduser("~")
        files = filedialog.askopenfilenames(
            title="Selecione os arquivos de wordlist",
            initialdir=initial_dir,
            filetypes=(("Arquivos de texto", "*.txt"), ("Todos os arquivos", "*.*"))
        )
        
        for file in files:
            if file not in self.wordlist_files:
                self.wordlist_files.append(file)
                self.wordlist_listbox.insert(tk.END, os.path.basename(file))
        
        self.update_stats()
    
    def remove_wordlists(self):
        selected = self.wordlist_listbox.curselection()
        for index in selected[::-1]:  # Remover em ordem reversa para evitar problemas de indexação
            del self.wordlist_files[index]
            self.wordlist_listbox.delete(index)
        self.update_stats()
    
    def update_stats(self):
        total_passwords = self.estimate_total_passwords()
        self.stats_var.set(f"Wordlists: {len(self.wordlist_files)} | Senhas estimadas: {total_passwords:,}")
    
    def estimate_total_passwords(self):
        """Estima o número total de senhas em todas as wordlists"""
        total = 0
        for file in self.wordlist_files:
            try:
                with open(file, 'rb') as f:
                    # Usa mmap para contagem eficiente de linhas
                    buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                    total += sum(1 for _ in buf)
            except:
                continue
        return total
    
    def log_message(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.root.update()
    
    def start_cracking(self):
        if not self.zip_file:
            messagebox.showerror("Erro", "Selecione um arquivo ZIP!")
            return
            
        if not self.wordlist_files:
            messagebox.showerror("Erro", "Adicione pelo menos uma wordlist!")
            return
            
        try:
            threads = int(self.threads_var.get())
            if threads < 1 or threads > self.max_threads * 2:
                raise ValueError
        except ValueError:
            messagebox.showerror("Erro", f"Número de threads inválido (1-{self.max_threads * 2})")
            return
            
        try:
            self.batch_size = int(self.batch_var.get())
            if self.batch_size < 100 or self.batch_size > 100000:
                raise ValueError
        except ValueError:
            messagebox.showerror("Erro", "Tamanho do lote inválido (100-100000)")
            return
        
        # Configuração inicial
        self.found = False
        self.running = True
        self.tested = 0
        self.passwords_tested = 0
        self.start_time = time.time()
        self.password_cache = []
        self.active_wordlists = 0
        
        # Atualizar interface
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress.config(value=0, maximum=100)
        
        # Iniciar processo
        self.log_message(f"[*] Iniciando ataque ao arquivo: {self.zip_file}")
        self.log_message(f"[*] Wordlists selecionadas: {len(self.wordlist_files)}")
        self.log_message(f"[*] Configuração: {threads} threads, lotes de {self.batch_size} senhas")
        
        # Criar executor de threads
        self.executor = ThreadPoolExecutor(max_workers=threads)
        
        # Iniciar workers para cada wordlist
        for wordlist in self.wordlist_files:
            self.active_wordlists += 1
            self.executor.submit(self.process_wordlist, wordlist)
        
        # Iniciar monitoramento
        self.monitor_progress()
    
    def process_wordlist(self, wordlist_file):
        """Processa uma wordlist em lotes para melhor desempenho"""
        try:
            self.log_message(f"[+] Processando wordlist: {os.path.basename(wordlist_file)}")
            
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                batch = []
                for line in f:
                    if not self.running:
                        break
                        
                    password = line.strip()
                    if password:
                        batch.append(password)
                        
                        # Quando o lote atinge o tamanho desejado, processa
                        if len(batch) >= self.batch_size:
                            self.process_batch(batch)
                            batch = []
                
                # Processa o último lote (menor que batch_size)
                if batch and self.running:
                    self.process_batch(batch)
            
        except Exception as e:
            self.log_message(f"[-] Erro ao processar {wordlist_file}: {str(e)}")
        finally:
            with self.cache_lock:
                self.active_wordlists -= 1
                if self.active_wordlists == 0 and not self.found:
                    self.log_message("[!] Todas as wordlists foram processadas, senha não encontrada")
                    self.stop_cracking()
    
    def process_batch(self, batch):
        """Processa um lote de senhas usando ThreadPoolExecutor"""
        futures = []
        for password in batch:
            if self.found or not self.running:
                break
                
            future = self.executor.submit(self.test_password, password)
            futures.append(future)
        
        # Atualiza contagem de senhas testadas
        with self.cache_lock:
            self.passwords_tested += len(batch)
    
    def test_password(self, password):
        """Testa uma senha no arquivo ZIP"""
        if self.found or not self.running:
            return False
            
        try:
            with zipfile.ZipFile(self.zip_file) as zf:
                # Tenta extrair o primeiro arquivo (mais eficiente que testar todos)
                for file_info in zf.infolist():
                    try:
                        zf.extract(file_info, pwd=password.encode())
                        # Se chegou aqui, a senha está correta
                        with self.cache_lock:
                            if not self.found:  # Verifica novamente para evitar condições de corrida
                                self.found = True
                                self.password_found(password)
                                return True
                    except (RuntimeError, zipfile.BadZipFile):
                        break  # Senha incorreta
                    except Exception as e:
                        self.log_message(f"[-] Erro ao testar senha: {str(e)}")
                        break
        except Exception as e:
            self.log_message(f"[-] Erro ao acessar arquivo ZIP: {str(e)}")
        
        return False
    
    def password_found(self, password):
        """Lida com a senha encontrada"""
        elapsed = time.time() - self.start_time
        speed = self.passwords_tested / elapsed if elapsed > 0 else 0
        
        self.log_message("\n[+] SENHA ENCONTRADA!")
        self.log_message(f"[+] Senha: {password}")
        self.log_message(f"[+] Tempo total: {elapsed:.2f} segundos")
        self.log_message(f"[+] Senhas testadas: {self.passwords_tested:,}")
        self.log_message(f"[+] Velocidade média: {speed:,.2f} senhas/segundo")
        
        messagebox.showinfo("Senha Encontrada", 
                          f"Senha encontrada: {password}\n\n"
                          f"Tempo: {elapsed:.2f}s\n"
                          f"Senhas testadas: {self.passwords_tested:,}\n"
                          f"Velocidade: {speed:,.2f} senhas/seg")
        
        self.stop_cracking(success=True)
    
    def monitor_progress(self):
        """Atualiza a interface com o progresso atual"""
        if not self.running:
            return
            
        elapsed = time.time() - self.start_time
        speed = self.passwords_tested / elapsed if elapsed > 0 else 0
        
        # Atualizar estatísticas
        self.speed_var.set(f"Velocidade: {speed:,.2f} senhas/segundo")
        self.progress["value"] = (self.passwords_tested / max(1, self.estimate_total_passwords())) * 100
        
        # Continuar monitorando
        if not self.found and self.running:
            self.root.after(500, self.monitor_progress)
    
    def stop_cracking(self, success=False):
        """Para o processo de cracking"""
        self.running = False
        self.found = success
        
        if self.executor:
            self.executor.shutdown(wait=False)
        
        # Atualizar interface
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        if not success:
            elapsed = time.time() - self.start_time
            speed = self.passwords_tested / elapsed if elapsed > 0 else 0
            self.log_message("\n[!] Processo interrompido")
            self.log_message(f"[+] Senhas testadas: {self.passwords_tested:,}")
            self.log_message(f"[+] Velocidade média: {speed:,.2f} senhas/segundo")

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedZIPPasswordCracker(root)
    root.mainloop()