# Part 3 of UWCSE's Mininet-SDN project
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

log = core.getLogger()

# Convenience mappings of hostnames to ips
IPS = {
    "h10": "10.0.1.10",
    "h20": "10.0.2.20",
    "h30": "10.0.3.30",
    "serv1": "10.0.4.10",
    "hnotrust": "172.16.10.100",
}

# Convenience mappings of hostnames to subnets
SUBNETS = {
    "h10": "10.0.1.0/24",
    "h20": "10.0.2.0/24",
    "h30": "10.0.3.0/24",
    "serv1": "10.0.4.0/24",
    "hnotrust": "172.16.10.0/24",
}


class Part3Controller(object):
    """
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        print(connection.dpid)
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)
        # use the dpid to figure out what switch is being created
        if connection.dpid == 1:
            self.s1_setup()
        elif connection.dpid == 2:
            self.s2_setup()
        elif connection.dpid == 3:
            self.s3_setup()
        elif connection.dpid == 21:
            self.cores21_setup()
        elif connection.dpid == 31:
            self.dcs31_setup()
        else:
                print("UNKNOWN SWITCH")
            exit(1)

    def s1_setup(self):
        # put switch 1 rules here
        self.install_flow(out_port = of.OFPP_FLOOD)       

    def s2_setup(self):
        # put switch 2 rules here
        self.install_flow(out_port = of.OFPP_FLOOD)       

    def s3_setup(self):
        # put switch 3 rules here
        self.install_flow(out_port = of.OFPP_FLOOD)       

    def cores21_setup(self):
        # put core switch rules here

        # Let ARP through 
        self.install_flow(priority=50, dl_type=0x0806, out_port=of.OFPP_FLOOD)
        
        # block ipv4 traffic from untrusted host to serv1
        self.install_flow(priority=300, 
                          dl_type=0x0800, 
                          nw_src=IPS["hnotrust"],
                          nw_dst=IPS["serv1"]) 

        # block untrusted ICMP 
        for host in("h10", "h20", "h30", "serv1"):
            self.install_flow(priority = 200, 
                              dl_type = 0x0800,
                              nw_proto = 1, 
                              nw_src = IPS["hnotrust"]
                              nw_dst = IPS[host])

        # Forward IP packets to port of destination host 
        destination_ports = {
            "h10": 1, 
            "h20": 2, 
            "h30": 3, 
            "serv1": 4, 
            "hnotrust": 5
        } 

        for host, port in destination_ports.items():
            self.install_flow(
                priority = 100, 
                dl_type = 0x0800, 
                nw_dst = IPS[host],
                out_port = port
            ) 




    def dcs31_setup(self):
        # put datacenter switch rules here
        self.install_flow(out_port = of.OFPP_FLOOD)       

    def install_flow(self, priority = 0,
                    dl_type = None, 
                    nw_src = None,
                    nw_dst = None,
                    nw_proto =None,
                    out_port = None):

        msg = of.ofp_flow_mod()
        msg.priority = priority

        if dl_type is not None: 
            msg.match.dl_type = dl_type
        if nw_src is not None:
            msg.match.nw_src = IPAddr(nw_src)
        if nw_dst is not None: 
            msg.match.nw_dst = IPAddr(nw_dst) 
        if nw_proto is not None:
            msg.match.nw_proto = nw_proto 

        # drop if dosen't match anything 
        if out_port is not None:
            msg.actions.append(of.ofp_action_output(port=out_port)) 

        self.connection.send(msg) 

    # used in part 4 to handle individual ARP packets
    # not needed for part 3 (USE RULES!)
    # causes the switch to output packet_in on out_port
    def resend_packet(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    def _handle_PacketIn(self, event):
        """
        Packets not handled by the router rules will be
        forwarded to this method to be handled by the controller
        """

        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.
        print(
            "Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump()
        )


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part3Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
