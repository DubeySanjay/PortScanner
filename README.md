# PortScanner
A port scanner is a program that automatically detects security weaknesses in a remote or localhost. When hackers attack a site, they often try each port in turn to see which are available and not blocked by a firewall or TCP wrapper. This scan can be recognized by a series of packets from one host to another in a short period of time. Port scans are aimed at many different ports, often in an increasing or decreasing sequence. This project involves the implementation of a port scan detector.

#If you reached till here, you have made it.

#Documentation

The applications is parsing the entire pcap file entry by entry and storing metadatas in a dictionary as:
	Key: IP address of the scanner
	Value:  - count of all flags (SYN, ACK, SYN-ACK, RST, ICMP)
			- stores all the ports accessed by this Key (IP address)
			- list of all packets that includes timestamps (for further analisys)
			- the timestamp of the first packet
			- the timestamp of the last packet
			- the scan type (auxilliary value - it is decided further in the code)
			- the scan phase (which step is the scan into? SYN? SYN-ACK? etc)

Based on the order the packets come, deduced from the scan phase and the current packet that is analysed the scan type is decided. For example:
Since the TCP SYN has only SYN followed by SYN-ACK followed by (or not) by RST and TCP CONNECT has an ACK after SYN-ACK, we can easily deduce that the presence of the ACK will point to the TCP CONNECT while the lack of it will point to TCP SYN.

For the attack duration we can just calculate  the timestamp of the last packet - the timestamp of the first packet easily, since the data is provided in the dictionary.

For the data visualization, it is used matplotlib and the information plotted is the pair (timestamp of the packet + packet type), where packet type is either SYN, ACK, SYN-ACK, RST or ICMP

#Project contain:

I. main.py : Python file
II. Documentation.txt: report
III. output.txt: sample output
IV. requirement.txt: environment to be installed
V. Technical analysis: Initial analysis apart from python and interpretation. 


#STEPS:

a. Unarchive zip file.

b. locate path to file(cmd/terminal).

c. Run following command:

1. requirements.txt: for creating programming environment.
	-> pip install -r requirements.txt
2. main.py- python file containing code
	-> python main.py test.pcap
	test.pcap can be any file that needs scan and detection.

It should pop up visualization along with result displayed in terminal/cmd.


In case nothing work out

-Sanjay Kumar Dubey
