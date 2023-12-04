import streamlit as st
import mysql.connector
from mysql.connector import Error
import pandas as pd

# Function to fetch data from MySQL
def fetch_data(query, params=None):
    connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Bandeya1234*",
        database="DBMS_project"
    )
    cursor = connection.cursor()
    
    if params:
        cursor.execute(query, params)
    else:
        cursor.execute(query)
    
    data = cursor.fetchall()
    cursor.close()
    connection.close()
    return data, cursor.description  # Include cursor.description in the return

# Function to calculate packets per second
def calculate_packets_per_second(packets):
    total_packets = len(packets)

    if total_packets <= 1:
        return "Not enough data to calculate packets per second"

    start_time = packets[0][3]
    end_time = packets[-1][3]
    duration = (end_time - start_time).seconds

    if duration == 0:
        return "Duration too short to calculate packets per second"

    packets_per_second = total_packets / duration
    return packets_per_second

# Function to display all tables
def display_all_tables():
    tables = ['Packets', 'Connection_details', 'Router', 'ARP_table', 'Devices_on_interface']

    for table in tables:
        st.write(f"Table: {table}")
        query = f"SELECT * FROM {table}"
        table_data, columns = fetch_data(query)  # Include cursor.description in the return
        df_table = pd.DataFrame(table_data, columns=[desc[0] for desc in columns])
        st.dataframe(df_table)

# Function to display the router a packet is in contact with
def display_packet_router_contact():
    query = """
        SELECT p.PacketID, c.Destination_MAC, r.Router_MAC
        FROM Packets p
        JOIN Connection_details c ON p.PacketID = c.PacketID
        JOIN Router r ON r.Device_MAC = c.Destination_MAC
        WHERE p.PacketID = c.PacketID;
    """

    try:
        data, _ = fetch_data(query)
        df_data = pd.DataFrame(data, columns=['PacketID', 'Destination MAC','Router_MAC'])
        st.dataframe(df_data)
    except Exception as e:
        st.error(f"Error fetching data: {e}")

# Function to insert a packet ID
def insert_packet(packet_id):
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Bandeya1234*",
            database="DBMS_project"
        )

        cursor = connection.cursor()
        cursor.callproc('insert_packet', (packet_id,))
        connection.commit()
        st.success(f"PacketID {packet_id} inserted successfully!")
    except Error as e:
        st.error(f"Error inserting PacketID: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def display_packets_per_interface():
    query = """
        SELECT Interface, COUNT(*) AS PacketCount
        FROM devices_on_interface
        GROUP BY Interface;
    """

    try:
        data, _ = fetch_data(query)
        df_data = pd.DataFrame(data, columns=['Interface', 'PacketCount'])
        st.dataframe(df_data)
    except Exception as e:
        st.error(f"Error fetching data: {e}")

def get_packet_count_for_ip():
    query = """
        SELECT Destination_IP, COUNT(*) AS Occurrences
        FROM packets
        GROUP BY Destination_IP;
    """

    try:
        data, _ = fetch_data(query)
        df_data = pd.DataFrame(data, columns=['Destination_IP', 'Occurrences'])
        st.dataframe(df_data)
    except Exception as e:
        st.error(f"Error fetching data: {e}")


def display_sequence_per_interface():
    print("Inside display_sequence_per_interface function")
    query = """
        SELECT doi.IP_Address, c.Sequence_number
        FROM Devices_on_interface doi
        JOIN Connection_details c ON doi.Device_MAC = c.Destination_MAC
        ORDER BY doi.IP_Address, c.Sequence_number;
    """

    try:
        data = fetch_data(query)
        print(f"Data fetched successfully: {data}")
        df_data = pd.DataFrame(data, columns=['IP_Address', 'Sequence_number'])
        st.dataframe(df_data)
    except Exception as e:
        st.error(f"Error fetching data: {e}")



def delete_router():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Bandeya1234*",
            database="DBMS_project"
        )

        cursor = connection.cursor()
        # Attempt to delete a record from the Router table
        cursor.execute("DELETE FROM Router")
        connection.commit()
        st.success("Deletion from Router table successful")
    except Error as e:
        st.error(f"Error deleting: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Streamlit app
st.title('Packet Analyzer')

# Example Dropdowns
selected_option = st.selectbox('Choose an Option', ['Select', 'Packet Speed', 'All Tables', 'Packet Router Contact', 'Insert Packet','Packets per Interface',   'Get Packet Count for IP', 'Delete Router records'])

# Display data based on the selected option
if selected_option == 'Packet Speed':
    # Fetch packets data
    query = "SELECT * FROM Packets ORDER BY Time_Stamp ASC"
    packets_data, _ = fetch_data(query)  # Include cursor.description in the return

    # Display packets per second
    packets_per_second = calculate_packets_per_second(packets_data)

    # Display the total number of packets and packets per second
    st.write(f'Total Packets: {len(packets_data)}')
    st.write(f'Packets per Second: {packets_per_second}')

    # Display the packets table
    df_packets = pd.DataFrame(packets_data, columns=['PacketID', 'Source_IP', 'Destination_IP', 'Time_Stamp'])
    st.dataframe(df_packets)

elif selected_option == 'All Tables':
    display_all_tables()

elif selected_option == 'Packet Router Contact':
    display_packet_router_contact()

elif selected_option == 'Insert Packet':
    packet_id = st.text_input('Enter PacketID to insert:')
    if st.button('Insert PacketID'):
        insert_packet(packet_id)

elif selected_option == 'Packets per Interface':
    display_packets_per_interface()

elif selected_option == 'Get Packet Count for IP':
    if st.button('Get Packet Count'):
        get_packet_count_for_ip()

elif selected_option == 'Sequence through IP':
    display_sequence_per_interface()

elif selected_option == 'Delete Router records':
    delete_router()

