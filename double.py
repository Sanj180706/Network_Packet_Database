import scapy.all as scapy
from scapy.layers.l2 import Ether
import mysql.connector
import random

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'PWD',
    'database': 'DBMS_project',
}

interfaces = [1, 2, 3, 4, 5]

arp_mac_addresses = [
    '00:11:22:33:44:55',
    'AA:BB:CC:DD:EE:FF',
    '11:22:33:44:55:66',
    'AA:BB:CC:DD:EE:11',
    '00:11:22:33:44:66',
]

device_mac = None
router_mac = None
router_interface = None

def insert_router_data(router_data):
    global device_mac, router_mac, router_interface

    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        existing_query = "SELECT Router_MAC, Interface FROM router WHERE Device_MAC = %s"
        cursor.execute(existing_query, (device_mac,))
        existing_record = cursor.fetchone()

        if existing_record:
            router_data = (existing_record[0], existing_record[1], device_mac, router_data[1])
        else:
            router_data = (random.choice(arp_mac_addresses), random.choice(interfaces), device_mac, router_data[1])

            query = "INSERT INTO router (Router_MAC, Interface, Device_MAC, Sequence_number) " \
                    "VALUES (%s, %s, %s, %s)"
            cursor.execute(query, router_data)
            connection.commit()

        cursor.fetchall()

        router_mac, router_interface = router_data[0], router_data[1]

    except mysql.connector.Error as err:
        print(f"Error: {err}")

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def insert_arp_data(arp_data):
    global device_mac, router_mac, router_interface

    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        existing_query = "SELECT * FROM arp_table WHERE Device_MAC = %s"
        cursor.execute(existing_query, (device_mac,))
        existing_record = cursor.fetchone()

        if not existing_record:
            query = "INSERT INTO arp_table (MAC_Address, Device_MAC, Device_IP, TTL, Protocol, Host_Name, Interface) " \
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)"
            arp_data = (router_mac, device_mac, arp_data[2], arp_data[3], arp_data[4], arp_data[5], router_interface)
            cursor.execute(query, arp_data)
            connection.commit()
        else:
            print(f"Duplicate record found for Device_MAC {device_mac} in arp_table. Skipping insertion.")

    except mysql.connector.Error as err:
        print(f"Error: {err}")

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()



def insert_device_data(device_data):
    global device_mac, router_mac

    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        existing_query = "SELECT * FROM devices_on_interface WHERE Device_MAC = %s AND Interface = %s"
        cursor.execute(existing_query, (device_mac, device_data[0]))
        existing_record = cursor.fetchone()

        if not existing_record:
            query = "INSERT INTO devices_on_interface (Device_MAC, Interface, IP_Address, Device_Name) " \
                    "VALUES (%s, %s, %s, %s)"
            device_data = (device_mac, device_data[0], device_data[1], "Unknown")
            cursor.execute(query, device_data)
            connection.commit()
        else:
            print(f"Duplicate record found for Device_MAC {device_mac} in devices_on_interface. Skipping insertion.")

    except mysql.connector.Error as err:
        print(f"Error: {err}")

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()


def packet_callback(packet):
    global device_mac, router_mac, router_interface

    if scapy.IP in packet:
        src_ip = packet[scapy.IP].src
        device_interface = random.choice(interfaces)
        device_mac = get_device_mac(src_ip, packet)
        packet_id = get_packet_id(packet)
        insert_router_data((device_mac, packet_id))
        insert_arp_data((random.choice(arp_mac_addresses), device_mac, src_ip, packet[scapy.IP].ttl,
                         packet[scapy.IP].proto, "Unknown", "Unknown"))  
        insert_device_data((router_interface, src_ip))

def get_packet_id(packet):
    return hash(str(packet))

def get_device_mac(ip_address, packet):
    return packet[Ether].src  

scapy.sniff(prn=packet_callback, store=0, timeout=5)
