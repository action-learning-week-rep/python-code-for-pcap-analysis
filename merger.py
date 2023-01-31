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


def long_push_time(array):
    push = []
    for i in range(len(array) - 1):
        time = (array[i + 1] - array[i])
        push.append(time)
    try:
        return max(push)
    except:
        pass


def total_pushtime(array):
    time = 0
    for i in range(len(array) - 1):
        time = time + (array[i + 1] - array[i])

    try:
        return time
    except:
        pass


# ---------------------------calculating number of tcp stream per client and there size for traffic-------------------------------
list_of_files = []
for file in os.listdir(f"./{dirctory}"):
    list_of_files.append(file)
list_all_streams = []
print("all streams have been read")
for onefile in list_of_files:
    streams = rdpcap(f"./{dirctory}/{onefile}")
    start_time = streams[0].time
    end_time = streams[-1].time
    total_stream_time = end_time - start_time
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

detected = list_filtered_list
with open(f"{dirctory}+.csv", "w") as filecsv:
    filednames = detected[0].keys()
    print(filednames)
    write = csv.DictWriter(filecsv, fieldnames=filednames)
    write.writeheader()
    for row in detected:
        write.writerow(row)
