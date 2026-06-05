import time
import random
from pymodbus.client import ModbusTcpClient

print("Estación de Ingeniería: Iniciando bucle de supervisión OT...")

while True:
    try:
        c = ModbusTcpClient('192.168.200.10', port=5020)
        if c.connect():
            c.read_holding_registers(address=0, count=15)
            c.read_coils(address=0, count=5)
            c.close()
            print('Workstation: lectura OK')
    except Exception as e:
        print(f'Workstation error: {e}')
    
    time.sleep(random.uniform(3, 8))

