from scapy.all import *
import csv
import pyshark
import os

dirctory = "1024enc"
server_ip = "192.168.1.62"


def push_time_avg(array):
    time = 0
    for i in range(len(array) - 1):
        time = time + (array[i + 1] - array[i])
    try:
        return time / (len(array) - 1)
    except:
        pass


    # The longest push time in the stream

        # This function long_push_time(array) calculates the longest time between consecutive elements in an input array of time stamps array.
        # It does this by subtracting each consecutive element (i+1) with the previous one (i) and appending the difference to a list push.
        # The function then returns the maximum value from the push list as the longest time between consecutive elements.
        # If the push list is empty, the function returns None.
    
def long_push_time(array):
    push = []
    for i in range(len(array) - 1):
        time = (array[i + 1] - array[i])
        push.append(time)
    try:
        return max(push)
    except:
        pass

    
# The function total_pushtime(array) takes an input array and calculates the total push time between consecutive elements in the array.
# It adds up the difference between each element and the next one using a loop, and returns the sum of these differences as the total push time.
# The try-except block is used to catch any exceptions that might occur during the calculation and return None if an exception is caught.

def total_pushtime(array):
    time = 0
    for i in range(len(array) - 1):
        time = time + (array[i + 1] - array[i])

    try:
        return time
    except:
        pass


# ---------------------------calculating number of tcp stream per client and there size for traffic-------------------------------
list_of_files = [] # Initialize an empty list to store the names of files in the specified directory.
for file in os.listdir(f"./{dirctory}"):
    list_of_files.append(file)  # Loop through the list of files in the specified directory (dirctory).
list_all_streams = [] # Initialize an empty list to store the results of processing each file.
print("all streams have been read") # Print a message indicating that all streams have been read.
for onefile in list_of_files:
    streams = rdpcap(f"./{dirctory}/{onefile}")
    start_time = streams[0].time
    end_time = streams[-1].time
    total_stream_time = end_time - start_time # Calculate the total time of the streams by subtracting the start time from the end time and store the result in the total_stream_time variable.
    number_of_packets = len(streams)
    number_flags_push = 0
    list_push_times = []
    for stream in streams:
        if stream["TCP"].flags == "PA":
            push_time = stream.time - start_time
            list_push_times.append(push_time)
            number_flags_push = number_flags_push + 1
    resualts = {"total stream time ": total_stream_time, "packets_per_stream:": number_of_packets,
                "push_flags": number_flags_push, "avg_push_time": push_time_avg(list_push_times),
                "total_push_time": total_pushtime(list_push_times),
                "longest_push_time": long_push_time(list_push_times)}
    list_all_streams.append(resualts)
print("first phase is done")
print(len(list_all_streams))


# 1.Reads a list of files in the specified directory (diretory).
# 2.Creates a list of packets by reading the contents of each file using the pyshark library.
# 3.Calculates the total TCP load (sum of packet lengths) for each file and adds it to the list_tcp_len.
# 4.Adds the total TCP load as an attribute to each item in the list_all_streams.
# 5.Filters the list_all_streams by removing the items with "push_flags" equal to 0.
# 6.Assigns the filtered list to the variable "detected".
# 7.Prints messages indicating that the second phase, filtration, and detection are done


list_of_packets = []
for file in list_of_files:
    tcp_total_load = 0
    cap = pyshark.FileCapture(f"./{dirctory}/{file}")
    list_of_packets.append(cap)

list_tcp_len = []
for i in list_of_packets:
    length = 0
    windowsizeinscaling = []
    for packet in i:

        try:
            if packet.tcp.flags == "0x0018" and packet.ip.src != server_ip:
                length = length + int(packet.tcp.len)
        except:
            pass

    list_tcp_len.append(length)
for i in range(len(list_all_streams)):
    val = {"tcp_len": list_tcp_len[i]}
    list_all_streams[i].update(val)

print("second phase is done")
# ------------------------------------------------------------------------------------------------------
serverip="192.168.1.62"
dirctory1="1024enc"
listat = []
list_of_files=[]
for file in os.listdir(f"./{dirctory1}"):
    list_of_files.append(file)
replaced_list=[]
for stream in list_of_files:
    cap = pyshark.FileCapture(f"./{dirctory1}/{stream}")
    replaced_list.append(cap)
for something in replaced_list:
    list_of_things = []
    for packet in something:
        try:
            if packet.ip.src == serverip and len(packet.tls.field_names) < 7 and packet.tcp.flags=="0x0018":
                listat.append(len(packet.tls.app_data))
                break
        except:
            pass
for i in range(len(listat)):
    val = {"appdata": listat[i]}
    list_all_streams[i].update(val)
modi=listat
modi.insert(0,0)
for i in range(len(modi)):
    val = {"appdata_p": modi[i]}
    list_all_streams[i].update(val)



# ---------------------------------------------------------------------------------------------------------
list_filtered_list = []
for i in list_all_streams:
    if i["push_flags"] == 0:
        print("nun found")
        continue
    else:
        list_filtered_list.append(i)
print("filtration is done")


# This code opens a new .csv file in write mode with the name dirctory+.csv using the open function and file handle
# filecsv. Then, it gets the keys of the first dictionary in the detected list as the fieldnames for the csv file. It
# uses the csv module's DictWriter class to write the fieldnames as the header of the csv file. Finally, it iterates
# through each row in the detected list, writing each dictionary in the list as a row in the csv file.
detected = list_filtered_list
with open(f"{dirctory}+.csv", "w") as filecsv:
    filednames = detected[0].keys()
    print(filednames)
    write = csv.DictWriter(filecsv, fieldnames=filednames)
    write.writeheader()
    for row in detected:
        write.writerow(row)
