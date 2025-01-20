# import time
# import psutil

# # Function to get all active network connections (TCP/UDP)
# def get_network_connections():
#     """Get all current network connections."""
#     try:
#         return psutil.net_connections(kind='inet')
#     except Exception as e:
#         print(f"Error fetching network connections: {e}")
#         return []

# # Function to get the application name for a given PID
# def get_application_name(pid):
#     try:
#         process = psutil.Process(pid)
#         return process.name()
#     except psutil.NoSuchProcess:
#         return None
#     except Exception as e:
#         print(f"Error fetching application name for PID {pid}: {e}")
#         return None

# # Function to monitor network connections for a specific application
# def monitor_network_for_app(app_name):
#     print(f"Monitoring network connection attempts for {app_name} (Press Ctrl+C to stop)...")
#     tracked_connections = set()  # Store already seen connections

#     try:
#         while True:
#             connections = get_network_connections()
#             for conn in connections:
#                 conn_tuple = (conn.pid, conn.laddr, conn.raddr)  # Unique identifier for a connection

#                 # Check if this connection attempt is new
#                 if conn_tuple not in tracked_connections:
#                     tracked_connections.add(conn_tuple)

#                     # Fetch details
#                     pid = conn.pid
#                     app_name_for_pid = get_application_name(pid)
#                     local_address = conn.laddr
#                     remote_address = conn.raddr if conn.raddr else 'N/A'
#                     status = conn.status

#                     # Filter by the specified application name
#                     if app_name_for_pid and app_name_for_pid.lower() == app_name.lower():
#                         print(f"New Attempt Detected for {app_name}:")
#                         print(f"App: {app_name_for_pid}, PID: {pid}, Local Address: {local_address}, "
#                               f"Remote Address: {remote_address}, Status: {status}")

#             # Wait for 1 second before checking again
#             time.sleep(1)

#     except KeyboardInterrupt:
#         print("\nMonitoring stopped.")
#     except Exception as e:
#         print(f"Error during monitoring: {e}")

# if __name__ == "__main__":
#     app_name = input("Enter the name of the application to monitor (e.g., chrome.exe, msedge.exe): ")
#     monitor_network_for_app(app_name)


# import time
# import psutil

# # Function to get all active network connections (TCP/UDP)
# def get_network_connections():
#     """Get all current network connections."""
#     try:
#         return psutil.net_connections(kind='inet')
#     except Exception as e:
#         print(f"Error fetching network connections: {e}")
#         return []

# # Function to get the application name for a given PID
# def get_application_name(pid):
#     try:
#         process = psutil.Process(pid)
#         return process.name()
#     except psutil.NoSuchProcess:
#         return None
#     except Exception as e:
#         print(f"Error fetching application name for PID {pid}: {e}")
#         return None

# # Function to monitor network connections for a specific application
# def monitor_network_for_app(app_name):
#     print(f"Monitoring network connection attempts for {app_name} (Press Ctrl+C to stop)...")
#     tracked_connections = set()  # Store already seen connections

#     try:
#         while True:
#             connections = get_network_connections()
#             for conn in connections:
#                 conn_tuple = (conn.pid, conn.laddr, conn.raddr)  # Unique identifier for a connection

#                 # Check if this connection attempt is new
#                 if conn_tuple not in tracked_connections:
#                     tracked_connections.add(conn_tuple)

#                     # Fetch details
#                     pid = conn.pid
#                     app_name_for_pid = get_application_name(pid)
#                     local_address = conn.laddr
#                     remote_address = conn.raddr if conn.raddr else 'N/A'
#                     status = conn.status

#                     # Filter by the specified application name
#                     if app_name_for_pid and app_name_for_pid.lower() == app_name.lower():
#                         # Check if the connection is an attempt (e.g., SYN_SENT or TIME_WAIT)
#                         if status in ['SYN_SENT', 'TIME_WAIT', 'CLOSE_WAIT']:
#                             connection_status = "Attempting to connect"
#                         else:
#                             connection_status = "Active connection"

#                         print(f"Connection Attempt Detected for {app_name}:")
#                         print(f"App: {app_name_for_pid}, PID: {pid}, Local Address: {local_address}, "
#                               f"Remote Address: {remote_address}, Status: {status}, Reason: {connection_status}")

#             # Wait for 1 second before checking again
#             time.sleep(1)

#     except KeyboardInterrupt:
#         print("\nMonitoring stopped.")
#     except Exception as e:
#         print(f"Error during monitoring: {e}")

# if __name__ == "__main__":
#     app_name = input("Enter the name of the application to monitor (e.g., chrome.exe, msedge.exe): ")
#     monitor_network_for_app(app_name)

# import time
# import psutil

# # Function to get all active network connections (TCP/UDP)
# def get_network_connections():
#     """Get all current network connections."""
#     try:
#         return psutil.net_connections(kind='inet')
#     except Exception as e:
#         print(f"Error fetching network connections: {e}")
#         return []

# # Function to get the application name for a given PID
# def get_application_name(pid):
#     try:
#         process = psutil.Process(pid)
#         return process.name()
#     except psutil.NoSuchProcess:
#         return None
#     except Exception as e:
#         print(f"Error fetching application name for PID {pid}: {e}")
#         return None

# # Function to monitor network connections for a specific application
# def monitor_network_for_app(app_name):
#     print(f"Monitoring network connection attempts for {app_name} (Press Ctrl+C to stop)...")
#     tracked_connections = set()  # Store already seen connections

#     try:
#         while True:
#             connections = get_network_connections()
#             for conn in connections:
#                 conn_tuple = (conn.pid, conn.laddr, conn.raddr)  # Unique identifier for a connection

#                 # Check if this connection attempt is new
#                 if conn_tuple not in tracked_connections:
#                     tracked_connections.add(conn_tuple)

#                     # Fetch details
#                     pid = conn.pid
#                     app_name_for_pid = get_application_name(pid)
#                     local_address = conn.laddr
#                     remote_address = conn.raddr if conn.raddr else 'N/A'
#                     status = conn.status
#                     protocol = "TCP" if conn.type == 1 else "UDP"  # TCP: 1, UDP: 2
#                     local_port = local_address[1]
#                     remote_port = remote_address[1] if remote_address != 'N/A' else 'N/A'

#                     # Filter by the specified application name
#                     if app_name_for_pid and app_name_for_pid.lower() == app_name.lower():
#                         # Check if the connection is an attempt (e.g., SYN_SENT or TIME_WAIT)
#                         if status in ['SYN_SENT', 'TIME_WAIT', 'CLOSE_WAIT']:
#                             connection_status = "Attempting to connect"
#                         else:
#                             connection_status = "Active connection"

#                         # Print detailed connection attempt information
#                         print(f"Connection Attempt Detected for {app_name}:")
#                         print(f"App: {app_name_for_pid}, PID: {pid}")
#                         print(f"Local Address: {local_address[0]}:{local_port}, Remote Address: {remote_address}, "
#                               f"Remote Port: {remote_port}, Status: {status}, Protocol: {protocol}")
#                         print(f"Reason: {connection_status}")

#             # Wait for 1 second before checking again
#             time.sleep(1)

#     except KeyboardInterrupt:
#         print("\nMonitoring stopped.")
#     except Exception as e:
#         print(f"Error during monitoring: {e}")

# if __name__ == "__main__":
#     app_name = input("Enter the name of the application to monitor (e.g., chrome.exe, msedge.exe): ")
#     monitor_network_for_app(app_name)


# import time
# import psutil
# from scapy.all import sniff, IP, TCP, UDP

# # Function to get all active network connections (TCP/UDP)
# def get_network_connections():
#     """Get all current network connections."""
#     try:
#         return psutil.net_connections(kind='inet')
#     except Exception as e:
#         print(f"Error fetching network connections: {e}")
#         return []

# # Function to get the application name for a given PID
# def get_application_name(pid):
#     try:
#         process = psutil.Process(pid)
#         return process.name()
#     except psutil.NoSuchProcess:
#         return None
#     except Exception as e:
#         print(f"Error fetching application name for PID {pid}: {e}")
#         return None

# # Function to monitor network connections for a specific application
# def monitor_network_for_app(app_name):
#     print(f"Monitoring network connection attempts for {app_name} (Press Ctrl+C to stop)...")
#     tracked_connections = set()  # Store already seen connections

#     try:
#         while True:
#             connections = get_network_connections()
#             for conn in connections:
#                 conn_tuple = (conn.pid, conn.laddr, conn.raddr)  # Unique identifier for a connection

#                 # Check if this connection attempt is new
#                 if conn_tuple not in tracked_connections:
#                     tracked_connections.add(conn_tuple)

#                     # Fetch details
#                     pid = conn.pid
#                     app_name_for_pid = get_application_name(pid)
#                     local_address = conn.laddr
#                     remote_address = conn.raddr if conn.raddr else 'N/A'
#                     status = conn.status
#                     protocol = conn.type
                    
#                     # Filter by the specified application name
#                     if app_name_for_pid and app_name_for_pid.lower() == app_name.lower():
#                         print(f"Connection Attempt Detected for {app_name}:")
#                         print(f"App: {app_name_for_pid}, PID: {pid}, Local Address: {local_address}, "
#                               f"Remote Address: {remote_address}, Status: {status}, Protocol: {protocol}")
#                         print("Packet Sniffing Details:")
#                         sniff(filter="ip", prn=lambda x: packet_callback(x, app_name_for_pid, pid), count=1)
#                         print("=" * 40)

#             # Wait for 1 second before checking again
#             time.sleep(1)

#     except KeyboardInterrupt:
#         print("\nMonitoring stopped.")
#     except Exception as e:
#         print(f"Error during monitoring: {e}")

# # Callback function for packet sniffing
# def packet_callback(pkt, app_name_for_pid, pid):
#     if IP in pkt:
#         # Check if the packet matches the app and PID
#         if pkt[IP].src and pkt[IP].dst:
#             print(f"Packet Captured - Source: {pkt[IP].src}:{pkt[IP].sport}, "
#                   f"Destination: {pkt[IP].dst}:{pkt[IP].dport}")
#             if TCP in pkt:
#                 print(f"TCP Packet - Flags: {pkt[TCP].flags}, Seq: {pkt[TCP].seq}, Ack: {pkt[TCP].ack}")
#                 print(f"Payload Data (Raw): {pkt[TCP].payload}")
#                 try:
#                     print(f"Payload Data (Decoded): {pkt[TCP].payload.load.decode()}")
#                 except:
#                     print("Payload could not be decoded.")
#             elif UDP in pkt:
#                 print(f"UDP Packet - Source Port: {pkt[UDP].sport}, Destination Port: {pkt[UDP].dport}")
#                 print(f"Payload Data (Raw): {pkt[UDP].payload}")
#                 try:
#                     print(f"Payload Data (Decoded): {pkt[UDP].payload.load.decode()}")
#                 except:
#                     print("Payload could not be decoded.")

# if __name__ == "__main__":
#     app_name = input("Enter the name of the application to monitor (e.g., chrome.exe, msedge.exe): ")
#     monitor_network_for_app(app_name)


import time
import psutil
from scapy.all import sniff, IP, TCP, UDP

# Function to get all active network connections (TCP/UDP)
def get_network_connections():
    """Get all current network connections."""
    try:
        return psutil.net_connections(kind='inet')
    except Exception as e:
        print(f"Error fetching network connections: {e}")
        return []

# Function to get the application name for a given PID
def get_application_name(pid):
    try:
        process = psutil.Process(pid)
        return process.name()
    except psutil.NoSuchProcess:
        return None
    except Exception as e:
        print(f"Error fetching application name for PID {pid}: {e}")
        return None

# Function to monitor network connections for a specific application
def monitor_network_for_app(app_name):
    print(f"Monitoring network connection attempts for {app_name} (Press Ctrl+C to stop)...")
    tracked_connections = set()  # Store already seen connections

    try:
        while True:
            connections = get_network_connections()
            if not connections:  # Handle case when no connections exist (e.g., internet is off)
                print(f"No active network connections detected. Checking for attempts...")
            
            for conn in connections:
                conn_tuple = (conn.pid, conn.laddr, conn.raddr)  # Unique identifier for a connection

                # Check if this connection attempt is new
                if conn_tuple not in tracked_connections:
                    tracked_connections.add(conn_tuple)

                    # Fetch details
                    pid = conn.pid
                    app_name_for_pid = get_application_name(pid)
                    local_address = conn.laddr
                    remote_address = conn.raddr if conn.raddr else 'N/A'
                    status = conn.status
                    protocol = conn.type

                    # Filter by the specified application name
                    if app_name_for_pid and app_name_for_pid.lower() == app_name.lower():
                        print(f"Connection Attempt Detected for {app_name}:")
                        print(f"App: {app_name_for_pid}, PID: {pid}, Local Address: {local_address}, "
                              f"Remote Address: {remote_address}, Status: {status}, Protocol: {protocol}")
                        
                        # Only sniff once for each new connection
                        print("Packet Sniffing Details:")
                        sniff(filter="ip", prn=lambda x: packet_callback(x, app_name_for_pid, pid), count=1, timeout=5)
                        print("=" * 40)

            # Wait for 1 second before checking again
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
    except Exception as e:
        print(f"Error during monitoring: {e}")

# Callback function for packet sniffing
def packet_callback(pkt, app_name_for_pid, pid):
    if IP in pkt:
        # Check if the packet matches the app and PID
        if pkt[IP].src and pkt[IP].dst:
            print(f"Packet Captured - Source: {pkt[IP].src}:{pkt[IP].sport}, "
                  f"Destination: {pkt[IP].dst}:{pkt[IP].dport}")
            if TCP in pkt:
                print(f"TCP Packet - Flags: {pkt[TCP].flags}, Seq: {pkt[TCP].seq}, Ack: {pkt[TCP].ack}")
                print(f"Payload Data (Raw): {pkt[TCP].payload}")
                try:
                    print(f"Payload Data (Decoded): {pkt[TCP].payload.load.decode()}")
                except:
                    print("Payload could not be decoded.")
            elif UDP in pkt:
                print(f"UDP Packet - Source Port: {pkt[UDP].sport}, Destination Port: {pkt[UDP].dport}")
                print(f"Payload Data (Raw): {pkt[UDP].payload}")
                try:
                    print(f"Payload Data (Decoded): {pkt[UDP].payload.load.decode()}")
                except:
                    print("Payload could not be decoded.")

if __name__ == "__main__":
    app_name = input("Enter the name of the application to monitor (e.g., chrome.exe, msedge.exe): ")
    monitor_network_for_app(app_name)


