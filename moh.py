from collections import Counter
from scapy.layers.http import HTTPRequest
from scapy.all import *
import csv
import pyshark
import statistics

dirctory = "httpflood"
server_ip = "192.168.1.62"


# Average push time in the stream

# The push_time_avg function takes an input of a list of times, called array.
# The function calculates the average time between pushes by iterating through the list and adding up the differences between consecutive elements in the list.
# The average is calculated by dividing the total time difference by the number of differences (i.e. the length of the list minus 1).
# The function returns the calculated average, but if an error occurs during the division, the function returns nothing by using a try-except block.


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


# This function will return a score based on the number of headers present in each HTTP request in a file.
# The score is defined as the maximum count of headers present in any HTTP request in the file.
# If there is no HTTP request in the file, the function returns -1.
def http_ligtimacy_score(file):
    http_legitimacy_score_list_per_request = []
    for packet in file:
        temp = []
        if HTTPRequest in packet:
            http_request = packet[HTTPRequest]
            method = http_request.Method
            host = http_request.Host
            path = http_request.Path
            user_agent = http_request.User_Agent
            Connection = http_request.Connection
            temp.append(Connection)
            accepte_encoding = http_request.Accept_Encoding
            accepte_language = http_request.Accept_Language
            content_length = http_request.Content_Length
            Accept_Charset = http_request.Accept_Charset
            Cookie = http_request.Cookie
            x_device_id = http_request.X_ATT_DeviceId
            temp.append(x_device_id)
            X_Correlation_ID = http_request.X_Correlation_ID
            temp.append(X_Correlation_ID)
            X_Csrf_Token = http_request.X_Csrf_Token
            temp.append(X_Csrf_Token)
            X_Forwarded_For = http_request.X_Forwarded_For
            temp.append(X_Forwarded_For)
            X_Forwarded_Host = http_request.X_Forwarded_Host
            temp.append(X_Forwarded_Host)
            X_Forwarded_Proto = http_request.X_Forwarded_Proto
            temp.append(X_Forwarded_Proto)
            X_Http_Method_Override = http_request.X_Http_Method_Override
            temp.append(X_Http_Method_Override)
            temp.append(X_Http_Method_Override)
            X_Request_ID = http_request.X_Request_ID
            temp.append(X_Request_ID)
            X_Requested_With = http_request.X_Requested_With
            temp.append(X_Requested_With)
            X_UIDH = http_request.X_UIDH
            temp.append(X_UIDH)
            X_Wap_Profile = http_request.X_Wap_Profile
            temp.append(X_Wap_Profile)
            Unknown_Headers = http_request.Unknown_Headers
            temp.append(Unknown_Headers)
            temp.append(method)
            temp.append(host)
            temp.append(path)
            temp.append(user_agent)
            temp.append(accepte_encoding)
            temp.append(accepte_language)
            temp.append(content_length)
            temp.append(Cookie)
            temp.append(Accept_Charset)
        http_legitimacy_score_list_per_request.append(temp)
    array_score = []
    for item in http_legitimacy_score_list_per_request:
        counter = 0
        if len(item) < 0:
            pass
        else:
            for indivdual in item:
                if indivdual == None:
                    pass
                else:
                    counter = counter + 1
        if counter > 0:
            array_score.append(counter)
    try:
        return max(array_score)
    except:
        return -1


# ---------------------------calculating number of tcp stream per client and there size for traffic-------------------------------
list_of_files = []  # Initialize an empty list to store the names of files in the specified directory.
for file in os.listdir(f"./{dirctory}"):
    list_of_files.append(file)  # Loop through the list of files in the specified directory (dirctory).
list_all_streams = []  # Initialize an empty list to store the results of processing each file.
print("all streams have been read")  # Print a message indicating that all streams have been read.
for onefile in list_of_files:
    streams = rdpcap(f"./{dirctory}/{onefile}")
    http_legitimacy_score_list_per_request = http_ligtimacy_score(
        streams)  # http_ligtimacy_score(streams): Call the http_ligtimacy_score function on the streams and store the result in the http_legitimacy_score_list_per_request variable.
    start_time = streams[0].time
    end_time = streams[-1].time
    total_stream_time = end_time - start_time  # Calculate the total time of the streams by subtracting the start time from the end time and store the result in the total_stream_time variable.
    number_of_packets = len(
        streams)  # Calculate the number of packets in the streams by getting the length of the streams list and store the result in the number_of_packets variable.
    number_flags_push = 0
    list_push_times = []
    for stream in streams:
        if stream["TCP"].flags == "PA":
            push_time = stream.time - start_time  # Calculate the time at which the "push" flag occurred by subtracting the start time from the current time and store the result in the push_time variable.
            list_push_times.append(push_time)
            number_flags_push = number_flags_push + 1
    resualts = {"total stream time ": total_stream_time,
                "packets_per_stream:": number_of_packets, "push_flags": number_flags_push,
                "avg_push_time": push_time_avg(list_push_times),
                "total_push_time": total_pushtime(list_push_times),
                "longest_push_time": long_push_time(list_push_times),
                "http_legitimacy_score_list_per_request": http_legitimacy_score_list_per_request}
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
        if packet.tcp.flags == "0x0018" and packet.ip.src != server_ip:
            length = length + int(packet.tcp.len)
    list_tcp_len.append(length)
for i in range(len(list_all_streams)):
    val = {"tcp_len": list_tcp_len[i]}
    list_all_streams[i].update(val)
print("second phase is done")
list_filtered_list = []
for i in list_all_streams:
    if i["push_flags"] == 0:
        print("nun found")
        continue
    else:
        list_filtered_list.append(i)
print("filtration is done")
detected = list_filtered_list
print("detection is done")

# This code opens a new .csv file in write mode with the name dirctory+.csv using the open function and file handle
# filecsv. Then, it gets the keys of the first dictionary in the detected list as the fieldnames for the csv file. It
# uses the csv module's DictWriter class to write the fieldnames as the header of the csv file. Finally, it iterates
# through each row in the detected list, writing each dictionary in the list as a row in the csv file.
with open(f"{dirctory}+.csv", "w") as filecsv:
    filednames = detected[0].keys()
    write = csv.DictWriter(filecsv, fieldnames=filednames)
    write.writeheader()
    for row in detected:
        write.writerow(row)
