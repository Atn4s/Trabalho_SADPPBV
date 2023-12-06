import sys
import locale
from http.server import SimpleHTTPRequestHandler, HTTPServer
import socket
import netifaces

locale.setlocale(locale.LC_ALL, 'pt_BR.UTF-8')

def get_local_ip():
    try:
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                for addr in addresses[netifaces.AF_INET]:
                    if 'addr' in addr:
                        if not addr['addr'].startswith('127.'):
                            return addr['addr']
        return 'localhost'
    except Exception as e:
        print(f"Erro ao obter o endereço IP local: {e}")
        return 'localhost'

class MyHTTPRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        SimpleHTTPRequestHandler.end_headers(self)

    def copyfile(self, source, outputfile):
        try:
            super().copyfile(source, outputfile)
        except BrokenPipeError:
            pass

if len(sys.argv) > 1:
    try:
        port = int(sys.argv[1])
    except ValueError:
        print("Porta inválida. Certifique-se de fornecer um número de porta válido.")
        sys.exit(1)
else:
    port = 8000

local_ip = get_local_ip()

try:
    server = HTTPServer((local_ip, port), MyHTTPRequestHandler)
    print(f'Servidor iniciado em http://{local_ip}:{port}')
    server.serve_forever()
except KeyboardInterrupt:
    print('^C recebido, desligando o servidor')
    server.socket.close()
