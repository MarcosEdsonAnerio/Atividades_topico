#!/usr/bin/env python3
import os
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

class FolderCompressorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Compactador de Pastas/Arquivos")
        self.root.geometry("650x500")
        
        # Variáveis
        self.caminho_origem = ""
        self.senha = ""
        self.tipo_compactacao = "zip"
        self.nivel_compressao = 6
        
        # Interface
        self.criar_interface()
        self.verificar_dependencias()
    
    def criar_interface(self):
        main_frame = tk.Frame(self.root, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Seleção do item a compactar
        tk.Label(main_frame, text="Arquivo ou Pasta para compactar:").pack(anchor=tk.W)
        frame_selecao = tk.Frame(main_frame)
        frame_selecao.pack(fill=tk.X, pady=5)
        
        self.origem_entry = tk.Entry(frame_selecao, width=50)
        self.origem_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        tk.Button(frame_selecao, text="Arquivo", command=self.selecionar_arquivo).pack(side=tk.LEFT, padx=5)
        tk.Button(frame_selecao, text="Pasta", command=self.selecionar_pasta).pack(side=tk.LEFT)
        
        # Configurações de compactação
        frame_config = tk.LabelFrame(main_frame, text="Configurações", padx=10, pady=10)
        frame_config.pack(fill=tk.X, pady=10)
        
        # Senha
        tk.Label(frame_config, text="Senha:").grid(row=0, column=0, sticky=tk.W)
        self.senha_entry = tk.Entry(frame_config, width=30, show="*")
        self.senha_entry.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # Tipo de compactação
        tk.Label(frame_config, text="Formato:").grid(row=1, column=0, sticky=tk.W)
        self.tipo_var = tk.StringVar(value="zip")
        tipos = [("ZIP", "zip"), ("RAR", "rar"), ("7z", "7z")]
        for i, (texto, valor) in enumerate(tipos):
            tk.Radiobutton(frame_config, text=texto, variable=self.tipo_var, value=valor).grid(row=1, column=i+1, sticky=tk.W)
        
        # Nível de compressão
        tk.Label(frame_config, text="Nível:").grid(row=2, column=0, sticky=tk.W)
        self.nivel_var = tk.IntVar(value=6)
        tk.Scale(frame_config, variable=self.nivel_var, from_=1, to=9, orient=tk.HORIZONTAL, length=200).grid(row=2, column=1, columnspan=3, sticky=tk.W)
        
        # Opções avançadas
        self.var_split = tk.BooleanVar()
        self.var_excluir_origem = tk.BooleanVar()
        self.var_manter_estrutura = tk.BooleanVar(value=True)
        
        tk.Checkbutton(frame_config, text="Dividir em volumes (MB):", variable=self.var_split).grid(row=3, column=0, sticky=tk.W)
        self.split_entry = tk.Entry(frame_config, width=10)
        self.split_entry.grid(row=3, column=1, sticky=tk.W)
        self.split_entry.insert(0, "100")
        
        tk.Checkbutton(frame_config, text="Excluir origens após compactar", variable=self.var_excluir_origem).grid(row=4, column=0, columnspan=2, sticky=tk.W)
        tk.Checkbutton(frame_config, text="Manter estrutura de pastas", variable=self.var_manter_estrutura).grid(row=4, column=2, columnspan=2, sticky=tk.W)
        
        # Botão de ação
        tk.Button(main_frame, text="COMPACTAR", command=self.compactar, 
                 bg="#4CAF50", fg="white", font=('Arial', 12, 'bold')).pack(pady=15)
        
        # Área de log
        tk.Label(main_frame, text="Log de Operação:").pack(anchor=tk.W)
        self.log_text = tk.Text(main_frame, height=10, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Barra de status
        self.status_var = tk.StringVar(value="Pronto")
        tk.Label(main_frame, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W).pack(fill=tk.X)
        
        # Configurar bindings
        self.var_split.trace_add("write", self.atualizar_ui)
        self.atualizar_ui()
    
    def atualizar_ui(self, *args):
        if self.var_split.get():
            self.split_entry.config(state=tk.NORMAL)
        else:
            self.split_entry.config(state=tk.DISABLED)
    
    def verificar_dependencias(self):
        for cmd, pkg in [("zip", "zip"), ("rar", "rar"), ("7z", "p7zip-full")]:
            if subprocess.run(["which", cmd], stdout=subprocess.PIPE).returncode != 0:
                self.log(f"Aviso: '{cmd}' não instalado. Para usar {pkg.upper()}, instale com: sudo apt install {pkg}")
    
    def selecionar_arquivo(self):
        self.caminho_origem = filedialog.askopenfilename(
            title="Selecione o arquivo para compactar",
            initialdir=os.path.expanduser("~/Desktop")
        )
        if self.caminho_origem:
            self.origem_entry.delete(0, tk.END)
            self.origem_entry.insert(0, self.caminho_origem)
    
    def selecionar_pasta(self):
        self.caminho_origem = filedialog.askdirectory(
            title="Selecione a pasta para compactar",
            initialdir=os.path.expanduser("~/Desktop")
        )
        if self.caminho_origem:
            self.origem_entry.delete(0, tk.END)
            self.origem_entry.insert(0, self.caminho_origem)
    
    def log(self, mensagem):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, mensagem + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.status_var.set(mensagem[:60] + "..." if len(mensagem) > 60 else mensagem)
        self.root.update()
    
    def compactar(self):
        origem = self.origem_entry.get()
        if not origem:
            messagebox.showerror("Erro", "Selecione um arquivo ou pasta!")
            return
        
        senha = self.senha_entry.get()
        tipo = self.tipo_var.get()
        nivel = self.nivel_var.get()
        
        # Sugerir nome padrão para o arquivo de saída
        nome_base = os.path.basename(origem.rstrip('/'))
        sugestao = f"{nome_base}.{tipo}" if os.path.isfile(origem) else f"{nome_base}_compactado.{tipo}"
        
        destino = filedialog.asksaveasfilename(
            title="Salvar arquivo compactado como",
            initialfile=sugestao,
            defaultextension=f".{tipo}",
            filetypes=[(f"Arquivo {tipo.upper()}", f"*.{tipo}")]
        )
        
        if not destino:
            return
        
        try:
            if tipo == "zip":
                self.criar_zip(origem, destino, senha, nivel)
            elif tipo == "rar":
                self.criar_rar(origem, destino, senha, nivel)
            elif tipo == "7z":
                self.criar_7z(origem, destino, senha, nivel)
            
            # Excluir origens se marcado
            if self.var_excluir_origem.get():
                if os.path.isfile(origem):
                    os.remove(origem)
                    self.log(f"Arquivo original removido: {origem}")
                else:
                    import shutil
                    shutil.rmtree(origem)
                    self.log(f"Pasta original removida: {origem}")
            
            messagebox.showinfo("Sucesso", f"Compactação concluída com sucesso!\n{destino}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha na compactação:\n{str(e)}")
            self.log(f"ERRO: {str(e)}")
    
    def criar_zip(self, origem, destino, senha, nivel):
        """Compacta para ZIP com suporte a pastas"""
        cmd = ["zip", "-r", "-X", f"-{nivel}"]
        
        if senha:
            cmd.extend(["-P", senha])
        
        if self.var_split.get():
            try:
                tamanho = int(self.split_entry.get())
                cmd.extend(["--split-size", f"{tamanho}m"])
                destino = destino.replace(".zip", ".zip")  # Para criar .z01, .z02, etc
            except ValueError:
                raise ValueError("Tamanho de volume inválido")
        
        cmd.append(destino)
        cmd.append(origem)
        
        self.log(f"Compactando para ZIP: {' '.join(cmd)}")
        resultado = subprocess.run(cmd, capture_output=True, text=True)
        
        if resultado.returncode != 0:
            raise Exception(resultado.stderr or "Erro desconhecido ao compactar")
        
        self.log(resultado.stdout)
    
    def criar_rar(self, origem, destino, senha, nivel):
        """Compacta para RAR com suporte a pastas"""
        if subprocess.run(["which", "rar"], stdout=subprocess.PIPE).returncode != 0:
            raise Exception("O programa 'rar' não está instalado. Instale com: sudo apt install rar")
        
        cmd = ["rar", "a", f"-m{nivel}", "-r", "-ep1"]  # -ep1 exclui caminhos base
        
        if senha:
            cmd.extend(["-hp" + senha])
        
        if self.var_split.get():
            try:
                tamanho = self.split_entry.get()
                cmd.extend(["-v" + tamanho + "m"])
            except ValueError:
                raise ValueError("Tamanho de volume inválido")
        
        if not self.var_manter_estrutura.get():
            cmd.append("-ep1")  # Exclui caminhos das pastas
        
        cmd.append(destino)
        cmd.append(origem)
        
        self.log(f"Compactando para RAR: {' '.join(cmd)}")
        resultado = subprocess.run(cmd, capture_output=True, text=True)
        
        if resultado.returncode != 0:
            raise Exception(resultado.stderr or "Erro desconhecido ao compactar")
        
        self.log(resultado.stdout)
    
    def criar_7z(self, origem, destino, senha, nivel):
        """Compacta para 7z com suporte a pastas"""
        if subprocess.run(["which", "7z"], stdout=subprocess.PIPE).returncode != 0:
            raise Exception("O programa '7z' não está instalado. Instale com: sudo apt install p7zip-full")
        
        cmd = ["7z", "a", "-t7z", f"-mx={nivel}", "-r"]
        
        if senha:
            cmd.extend(["-p" + senha, "-mhe=on"])  # -mhe=on protege cabeçalhos
        
        if self.var_split.get():
            try:
                tamanho = self.split_entry.get()
                cmd.extend(["-v" + tamanho + "m"])
            except ValueError:
                raise ValueError("Tamanho de volume inválido")
        
        if not self.var_manter_estrutura.get():
            cmd.append("-spf2")  # Nomes relativos sem caminho
        
        cmd.append(destino)
        cmd.append(origem)
        
        self.log(f"Compactando para 7z: {' '.join(cmd)}")
        resultado = subprocess.run(cmd, capture_output=True, text=True)
        
        if resultado.returncode != 0:
            raise Exception(resultado.stderr or "Erro desconhecido ao compactar")
        
        self.log(resultado.stdout)

if __name__ == "__main__":
    root = tk.Tk()
    app = FolderCompressorApp(root)
    root.mainloop()