import argparse
import itertools
import socket
from concurrent import futures
from typing import Optional

COD = "utf-8"
HOST = "localhost"


def parse_arguments():
    """Парсинг аргументов"""

    parser = argparse.ArgumentParser(
        description='Ports scanning script.\n '
                    'Input: python3 Scanner_ports_Mitrofanov.py -p [starting_port] [ending_port] -a [address]')
    parser.add_argument('-p', '--port', help='Starting and ending ports', nargs=2, type=int)
    parser.add_argument('-a', '--addr', help='IP address (default=localhost)', nargs=1, type=str, default="localhost")
    parse = parser.parse_args()
    return parse.port, parse.addr, True


def print_ports(ports: dict, start: int, end: int):
    """Вывод результата работы скрипта"""

    ports_tcp = ports.get("tcp")
    ports_udp = ports.get("udp")
    print(f"Interval: {start} - {end}")

    print(f"Number of TCP and UDP ports: {len(ports_tcp)}")
    for port_tcp, port_udp in itertools.zip_longest(ports_tcp, ports_udp, fillvalue=""):
        print(f"{port_tcp:<31} {port_udp}")


def check_arguments(first: int, last: int) -> bool:
    """Проверка на корректность введенных данных"""

    return 0 <= first <= 65535 and 0 <= last <= 65535


def scan_udp(port: int):
    """Создание UDP-сокета. Подлючение к портам на заданном хосте"""

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.01)
        try:
            sock.sendto("data".encode(COD), (HOST, port))
            sock.recvfrom(1024)
            return port
        except Exception as e:
            if e.errno != 10054 and e.errno is not None:
                return port
    return None


def scan_tcp(port: int) -> Optional[int]:
    """Создание TCP-сокета. Подлючение к портам на заданном хосте"""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.01)
        if s.connect_ex((HOST, port)) == 0:
            return port
    return None


def scanner(start: int, end: int) -> dict:
    """Императивное сканирование"""

    PORTS_UDP, PORTS_TCP = [], []
    for port in range(start, end + 1):
        if port_tcp := scan_tcp(port):
            PORTS_TCP.append(port_tcp)
        if port_udp := scan_udp(port):
            PORTS_UDP.append(port_udp)

    return {"tcp": PORTS_TCP, "udp": PORTS_UDP}


def concurrent_scanner(start: int, end: int) -> dict:
    """Асинхронное сканирование"""

    PORTS_TCP, PORTS_UDP = [], []

    with futures.ThreadPoolExecutor(max_workers=50) as executor:
        result_tcp = executor.map(scan_tcp, range(start, end + 1))
        result_udp = executor.map(scan_udp, range(start, end + 1))

        for port_tcp, port_udp in zip(result_tcp, result_udp):
            if port_tcp is not None:
                PORTS_TCP.append(port_tcp)
            if port_udp is not None:
                PORTS_UDP.append(port_udp)

    return {"tcp": PORTS_TCP, "udp": PORTS_UDP}


def main(port, is_concurrent):
    # time_start = time.time()
    if is_concurrent:
        ports = concurrent_scanner(*port)
    else:
        ports = scanner(*port)
    # print("\rWorking Time:", time.time() - time_start, "ms")

    print_ports(ports, *port)


if __name__ == "__main__":
    port, HOST, is_concurrent = parse_arguments()
    if type(HOST) == list:
        HOST = HOST[0]
    if check_arguments(*port):
        print(f'Scanning {HOST}')
        main(port, is_concurrent)
    else:
        print("\rIncorrect input.")
