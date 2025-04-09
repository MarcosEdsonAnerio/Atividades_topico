## Script de Instalação (`install.sh`)

```bash
#!/bin/bash
# Script de instalação para o Advanced Port Scanner

echo "Instalando dependências..."
sudo apt update
sudo apt install -y python3 python3-pip
pip3 install scapy netifaces

echo "Configurando permissões..."
sudo chmod +x advanced_scanner.py

echo "Instalação concluída!"
echo "Execute o scanner com: sudo python3 advanced_scanner.py"