#!/usr/bin/env python3


import random
from argparse import ArgumentParser

from rich import print
from rich.align import Align
from rich.console import Console
from rich.padding import Padding as RichPadding
from rich.panel import Panel
from rich.text import Text
from scapy.all import (PPP, Dot1Q, Ether, Padding,
                       PPP_LCP_Auth_Protocol_Option, PPP_LCP_Configure,
                       PPP_PAP_Request, PPPoE, PPPoED, PPPoED_Tags, PPPoETag,
                       RandString, get_if_hwaddr, sendp, sniff)


class Retriever:
    
    def __init__(self, interface, vlan):
        self.interface = interface
        self.vlan = vlan
        self.username = None
        self.password = None

        # Replace 'lo' with the appropriate loopback interface on your system
        sniff(prn=self.handle_eth_frame, iface=self.interface, lfilter=lambda pkg: pkg.haslayer(PPP) or pkg.haslayer(PPPoED), stop_filter=lambda pkg: pkg.haslayer(PPP_PAP_Request), store=0)

        
    def handle_eth_frame(self, packet):
        
        if PPPoED in packet:
            
            # If PADI packet reply with PADO
            if packet[PPPoED].code == 9:    
                self.send_pado_packet(packet, self.interface, self.vlan)

            # If PADR packet reply with PADS
            if packet[PPPoED].code == 25:
                self.send_pads_packet(packet, self.interface, self.vlan)
        
        elif PPPoE in packet:
            
            # If PADS then configure PPP_LCP
            if PPP_LCP_Configure in packet and packet[PPP_LCP_Configure].code == 1:
                self.stablish_ppp_lcp_config(packet, self.interface, self.vlan)
            
            # If PPP_PAP_Request store credentials
            elif PPP_PAP_Request in packet:
                self.username = packet[PPP_PAP_Request].username.decode()
                self.password = packet[PPP_PAP_Request].password.decode()
                

    @staticmethod
    def send_pado_packet(padi_packet, interface, vlan):
        
        # Extract the mac address of the interface
        src_mac = get_if_hwaddr(interface)
        
        # Get Host-Unig tag value
        if PPPoED_Tags in padi_packet:
            for tag in padi_packet[PPPoED_Tags].tag_list:
                if tag.tag_type == 259:  # Host-Uniq Tag
                    host_unique = tag.tag_value
        
        test = Ether(src=src_mac, dst=padi_packet[Ether].src)
        src=src_mac
        dst=padi_packet[Ether].src
        print(type(test))

        # Create of PADO packet
        pado_packet = ( Ether(src=src_mac, dst=padi_packet[Ether].src) /
            Dot1Q(prio=0, vlan=vlan) /
            PPPoED(code=7) /
            PPPoED_Tags(tag_list = [PPPoETag(tag_type=257, tag_value=""), PPPoETag(tag_type=258, tag_value="MyAccessConcentrator"), PPPoETag(tag_type=260, tag_value=RandString(16)), PPPoETag(tag_type=259, tag_value=host_unique)])
            #Padding(load=b'\x00' * 2)
            )
        
        # Send PADO packet
        sendp(pado_packet, iface=interface, verbose=False)

    @staticmethod
    def send_pads_packet(padr_packet, interface, vlan):
        
        # Get Host-Unig and AC-Cookie tag values
        if PPPoED_Tags in padr_packet:
            for tag in padr_packet[PPPoED_Tags].tag_list:
                if tag.tag_type == 259:  # Host-Uniq Tag
                    host_unique = tag.tag_value
                elif tag.tag_type == 260:  # AC-Cookie Tag
                    ac_cookie = tag.tag_value
        
        # Create of PADO packet
        packet = ( Ether(src=padr_packet[Ether].dst, dst=padr_packet[Ether].src) /
            Dot1Q(prio=0, vlan=vlan) /
            # Generate a random integer between 1 and 65535
            PPPoED(code=101, sessionid=random.randint(1, 0xFFFF)) /
            PPPoED_Tags(tag_list = [PPPoETag(tag_type=257, tag_value=""), PPPoETag(tag_type=260, tag_value=ac_cookie), PPPoETag(tag_type=259, tag_value=host_unique)])
            )

        # Send PADR packet
        sendp(packet, iface=interface, verbose=False)
    
        
    @staticmethod
    def stablish_ppp_lcp_config(pads_packet, interface, vlan):
        # Ether / Dot1Q / PPPoE / PPP / LCP Configure-Request / Padding

        config_ack_packet = ( Ether(src=pads_packet[Ether].dst, dst=pads_packet[Ether].src) /
            Dot1Q(prio=0, vlan=vlan) /
            # Generate a random integer between 1 and 65535
            PPPoE(sessionid=pads_packet[PPPoE].sessionid) /
            PPP() /
            PPP_LCP_Configure(code=2, id=pads_packet[PPP_LCP_Configure].id, options=pads_packet[PPP_LCP_Configure].options) /
            Padding(load=b'\x00' * 20)
            )
        
        # Send PPP_LCP config acknowledgment packet
        sendp(config_ack_packet, iface=interface, verbose=False)
        

        config_packet = ( Ether(src=pads_packet[Ether].dst, dst=pads_packet[Ether].src) /
            (Dot1Q(prio=0, vlan=pads_packet[Dot1Q].vlan) if Dot1Q in pads_packet else Dot1Q(prio=0, vlan=24)) /
            # Generate a random integer between 1 and 65535
            PPPoE(sessionid=pads_packet[PPPoE].sessionid) /
            PPP() /
            # id requires 0 <= number <= 255
            PPP_LCP_Configure(code=1, id=35, options=[PPP_LCP_Auth_Protocol_Option(),]) /
            Padding(load=b'\x00' * 26)
            )

        # Send PPP_LCP configuration packet
        sendp(config_packet, iface=interface, verbose=False)


def main():
    
    parser = ArgumentParser(description='Retrieves the PPPoE credentials from ISP-locked down routers.')
    
    parser.add_argument('-i', '--interface', type=str, required=True, help='interface to monitor on')
    parser.add_argument('-l', '--vlan', type=int, nargs='+', required=True, help='ethernet VLAN ID')
    #parser.add_argument('-v', '--version', help='version')
    
    args = parser.parse_args()
    
    console = Console()
    rtrv = None
    
    with console.status(f"Monitoring interface {args.interface} for PPPoE connection to be stablish", spinner="dots"):
        rtrv = Retriever(args.interface, args.vlan[0])
        
    result_message = f"Username: {rtrv.username}\nPassword: {rtrv.password}\n\n\nYou may need the VLAN configuration to complete the setup of your new router.\n\nVLAN: {rtrv.vlan}"

    panel = Panel(
            RichPadding(Align.center(Text(result_message, justify='center')), (4,2)),
            title="[bold red]PPPoE Credentials",
            subtitle="[italic underline]Author[reset]: [underline blue link https://guillermodotn.github.io]guillermodotn"
        )

    print(panel)


if __name__ == '__main__':
    main()