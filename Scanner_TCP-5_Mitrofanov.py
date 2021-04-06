import argparse
import socket


def parse_arguments() -> list:
    """Парсинг аргументов"""

    parser = argparse.ArgumentParser(
        description='Ports scanning script. Input: python3 ports_scan.py -p [starting_port] [ending_port]')
    parser.add_argument('-p', '--port', help='This will be starting and ending ports', nargs=2, type=int)
    return parser.parse_args().port


def print_ports(ports: set, first: int, last: int):
    """Вывод результата работы скрипта"""
    
    if len(ports) == 0:
        print("There are not open TCP ports in the range {} - {}.".format(first, last))
    else:
        print("Open TCP ports:")
        for port in ports:
            print(port)


def check_arguments(first: int, last: int) -> bool:
    """Проверка на корректность введенных данных"""

    return 0 <= first <= 65535 and 0 <= last <= 65535


def socket_scan_tcp(first: int, last: int) -> set:
    """Создание TCP-сокета. Подлючение к портам на локальном хосте"""
    
    ports = set()
    for port in range(first, last + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.01)
            if s.connect_ex(('localhost', port)) == 0:
                ports.add(port)
    return ports


if __name__ == "__main__":
    port = parse_arguments()
    if check_arguments(*port):
        print('Scanning...')
        print_ports(socket_scan_tcp(*port), *port)
    else:
        print("Некорректный ввод")
