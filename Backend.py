import scapy.all as scapy
import mysql.connector
from datetime import datetime, timedelta

# Function to insert data into the 'Packets' table
def insert_into_packets_table(data, cursor):
    try:
        columns = ', '.join(data.keys())
        values = ', '.join(['%s'] * len(data))
        query = f"INSERT INTO Packets ({columns}) VALUES ({values})"
        cursor.execute(query, tuple(data.values()))

        protocol = data.get('Protocol', 'Unknown')
        print(f"Data inserted into 'Packets' table successfully. Protocol: {protocol}")

    except Exception as e:
        print(f"Error inserting data into 'Packets' table: {e}")
        raise  # Re-raise the exception to trigger a rollback

# Function to insert data into the 'Connection_details' table
def insert_into_connection_details_table(data, cursor):
    try:
        columns = ', '.join(data.keys())
        values = ', '.join(['%s'] * len(data))
        query = f"INSERT INTO Connection_details ({columns}) VALUES ({values})"
        cursor.execute(query, tuple(data.values()))

        packet_id = data.get('PacketID', 'Unknown')
        print(f"Data inserted into 'Connection_details' table successfully. Packet ID: {packet_id}")

    except Exception as e:
        print(f"Error inserting data into 'Connection_details' table: {e}")
        raise  # Re-raise the exception to trigger a rollback

# Function to capture and process packets for a specified duration
def capture_packets(duration):
    end_time = datetime.now() + timedelta(seconds=duration)

    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Bandeya1234*",
            database="DBMS_project"
        )
        cursor = connection.cursor()

        while datetime.now() < end_time:
            packet = scapy.sniff(count=1)[0]

            try:
                source_ip = packet[scapy.IP].src
                destination_ip = packet[scapy.IP].dst
                time_stamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
                protocol = packet[scapy.IP].proto

                protocol_names = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
                protocol_name = protocol_names.get(protocol, 'Unknown')

                connection_details = packet[scapy.IP].payload
                sequence_number = connection_details.seq
                ttl = packet[scapy.IP].ttl
                source_mac = packet.src
                destination_mac = packet.dst
                source_port = connection_details.sport
                destination_port = connection_details.dport
                info = connection_details.payload.summary()
                length = len(connection_details.payload)
                packet_id = packet[scapy.IP].id

                # Start a transaction
                connection.start_transaction()

                # Insert data into 'Connection_details' table
                connection_data = {
                    'Sequence_number': sequence_number,
                    'Protocol': protocol_name,
                    'TTL': ttl,
                    'Source_MAC': source_mac,
                    'Destination_MAC': destination_mac,
                    'Source_port': source_port,
                    'Destination_port': destination_port,
                    'Info': info,
                    'Length': length,
                    'PacketID': packet_id
                }
                insert_into_connection_details_table(connection_data, cursor)

                # Insert data into 'Packets' table
                packet_data = {
                    'PacketID': packet_id,
                    'Source_IP': source_ip,
                    'Destination_IP': destination_ip,
                    'Time_Stamp': time_stamp
                }
                insert_into_packets_table(packet_data, cursor)

                # Commit the transaction
                connection.commit()

            except Exception as e:
                print(f"Error processing packet: {e}")

    except KeyboardInterrupt:
        print("Packet sniffing stopped by the user")

    finally:
        cursor.close()
        connection.close()

# Create tables if they don't exist
try:
    connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Bandeya1234*",
        database="DBMS_project"
    )
    cursor = connection.cursor()

    # First table is that of the packets
    cursor.execute("CREATE TABLE IF NOT EXISTS Packets("
                   "PacketID BIGINT NOT NULL, "
                   "Source_IP VARCHAR(15) NOT NULL CHECK (Source_IP REGEXP '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$'), "
                   "Destination_IP VARCHAR(15) NOT NULL CHECK (Destination_IP REGEXP '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$'), "
                   "Time_Stamp TIMESTAMP)")

    cursor.execute("CREATE TABLE IF NOT EXISTS Connection_details ("
                   "Sequence_number BIGINT NOT NULL, "
                   "Protocol ENUM('TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'SMTP', 'POP3', 'IMAP', 'DNS', 'FTP','Other') NOT NULL, "
                   "TTL BIGINT NOT NULL, "
                   "Source_MAC VARCHAR(17) NOT NULL, "
                   "Destination_MAC VARCHAR(17) NOT NULL, "
                   "Source_port BIGINT NOT NULL, "
                   "Destination_port BIGINT NOT NULL, "
                   "Info VARCHAR(1518), "
                   "Length BIGINT NOT NULL ,"
                   "PacketID bigint NOT NULL)"
                   )

    # Router table
    cursor.execute("CREATE TABLE IF NOT EXISTS Router ("
               "Router_MAC VARCHAR(17) NOT NULL, "
               "Device_MAC VARCHAR(17) NOT NULL, "
               "Interface INT(3) NOT NULL, "
               "Sequence_number BIGINT(10) NOT NULL, "
               "PRIMARY KEY (Router_MAC, Device_MAC, Interface), "
               "INDEX router_device_interface (Device_MAC, Interface))"
               )

# ARP_table table
    cursor.execute("CREATE TABLE IF NOT EXISTS ARP_table ("
               "MAC_Address VARCHAR(17) NOT NULL, "
               "Device_MAC VARCHAR(17) NOT NULL, "
               "Device_IP VARCHAR(15) NOT NULL, "
               "TTL BIGINT(10) NOT NULL, "
               "Protocol ENUM('TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'SMTP', 'POP3', 'IMAP', 'DNS', 'FTP','other') NOT NULL, "
               "Host_Name VARCHAR(20) NOT NULL, "
               "Interface INT(3) NOT NULL, "
               "PRIMARY KEY (MAC_Address, Device_MAC), "
               "INDEX arp_device_interface (Device_MAC, Interface), "
               "FOREIGN KEY (Device_MAC, Interface) REFERENCES Router(Device_MAC, Interface) ON DELETE CASCADE)"
               )


    # Devices_on_interface table
    cursor.execute("CREATE TABLE IF NOT EXISTS Devices_on_interface ("
               "Device_MAC VARCHAR(17) NOT NULL, "
               "Interface INT(3) NOT NULL, "
               "IP_Address VARCHAR(15) NOT NULL, "
               "Device_Name VARCHAR(255), "
               "PRIMARY KEY (Device_MAC, Interface), "
               "INDEX devices_interface (Device_MAC, Interface), "
               "FOREIGN KEY (Device_MAC, Interface) REFERENCES Router(Device_MAC, Interface) ON DELETE CASCADE)"
               )

    connection.commit()

except Exception as e:
    print(f"Error creating tables: {e}")

finally:
    cursor.close()
    connection.close()

# Capture packets for 20 seconds
capture_duration = 20
capture_packets(capture_duration)

# Display contents of the 'Packets' table
try:
    connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Bandeya1234*",
        database="DBMS_project"
    )
    cursor = connection.cursor()

    query = "SELECT * FROM Packets"
    cursor.execute(query)
    packets = cursor.fetchall()

    print("Contents of 'Packets' table:")
    for packet in packets:
        print(packet)

except Exception as e:
    print(f"Error querying 'Packets' table: {e}")

finally:
    cursor.close()
    connection.close()
