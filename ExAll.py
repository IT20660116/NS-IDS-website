from scapy.all import *
import csv
import mysql.connector

def extract_fields(packet):
    fields = []
    for field, value in packet.fields.items():
        if isinstance(value, (list, Packet)):
            fields.extend(extract_fields(value))
        else:
            fields.append((field, value))
    return fields

def packet_handler(packet):
    # Extract the necessary information from the packet
    if IP in packet:
        Version = packet[IP].version
        ihl = packet[IP].ihl
        tos = packet[IP].tos
        length = packet[IP].len
        packet_id = packet[IP].id
        flags = packet[IP].flags
        ttl = packet[IP].ttl
        proto = packet[IP].proto
        checksum = packet[IP].chksum
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport if TCP in packet else "N/A"
        dst_port = packet[TCP].dport if TCP in packet else "N/A"

        # Write the packet details to the CSV file
        with open('captured_packets.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            # Write the column headers if the file is empty
            if file.tell() == 0:
                writer.writerow(["Version", "IHL", "TOS", "Length", "ID", "Flags", "TTL", "Protocol", "Checksum", "Source IP", "Destination IP", "Source Port", "Destination Port"])
            writer.writerow([Version, ihl, tos, length, packet_id, flags, ttl, proto, checksum, src_ip, dst_ip, src_port, dst_port])

def insert_packets_to_database(csv_file, host, user, password, database, table):
    # Establish a connection to the MySQL database
    db = mysql.connector.connect(
        host=host,
        user=user,
        password=password,
        database=database
    )

    # Create a cursor object to interact with the database
    cursor = db.cursor()

    # Read the CSV file and insert the values into the database
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip the header row
        for row in reader:
            # Generate the SQL query to insert the values
            query = f"INSERT INTO {table} VALUES ({','.join('%s' for _ in range(len(row)))})"
            values = tuple(row)

            # Execute the SQL query to insert the values
            cursor.execute(query, values)

    # Commit the changes to the database
    db.commit()

    # Close the cursor and database connection
    cursor.close()
    db.close()

# Insert the packets from the CSV file into the database table
insert_packets_to_database('captured_packets.csv', '127.0.0.1', 'root', 'Sula!@#$1234ASS', 'instrution_detection', 'ip_details')    

# Sniff packets for a given duration of time (in seconds)
def sniff_packets(duration):
    # Start the packet capture
    packets = sniff(timeout=duration, prn=packet_handler)

    # Process the captured packets here
    # You can access packet details using packets[index]

# Sniff packets for 10 seconds
sniff_duration = 10
sniff_packets(sniff_duration)
