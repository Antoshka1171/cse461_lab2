# Part 4 of UWCSE's Mininet-SDN project
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet

log = core.getLogger()

# The MAC address cores21 uses as every subnet's gateway. Any MAC works:
# hosts only use it as the next-hop label, and cores21 rewrites it anyway.
ROUTER_MAC = EthAddr("00:00:00:00:00:21")

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


class Part4Controller(object):
    """
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # Routing table cores21 learns from ARP: host IP -> (MAC, port)
        self.routes = {}

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
        # Only the firewall rules are installed at startup. There are no
        # routes and no ARP rule: ARP goes to the controller (see
        # _handle_PacketIn), which learns hosts and installs routes then.

        # block ipv4 traffic from untrusted host to serv1
        self.install_flow(priority=300, 
                          dl_type=0x0800, 
                          nw_src=IPS["hnotrust"],
                          nw_dst=IPS["serv1"]
        ) 

        # block untrusted ICMP 
        for host in("h10", "h20", "h30", "serv1"):
            self.install_flow(priority = 200, 
                              dl_type = 0x0800,
                              nw_proto = 1, 
                              nw_src = IPS["hnotrust"],
                              nw_dst = IPS[host],
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

    # causes the switch to output packet_in on out_port
    # (used to send our ARP replies)
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

        # Only cores21 acts as a router; the other switches flood everything.
        if self.connection.dpid != 21:
            return

        # Every host only ARPs for its gateway, and cores21 pretends to be
        # every gateway. Anything else (e.g. IP to a host we have not learned
        # yet) is dropped; it will work once that host has sent an ARP.
        arp_packet = packet.find("arp")
        if arp_packet is None or arp_packet.opcode != arp.REQUEST:
            return

        self.learn_host(arp_packet.protosrc, arp_packet.hwsrc, event.port)
        self.send_arp_reply(arp_packet, event.port)

    def learn_host(self, ip, mac, port):
        """
        Remember where a host lives and install a route to it on cores21.
        """
        if self.routes.get(ip) == (mac, port):
            return  # already known, rule is already installed
        self.routes[ip] = (mac, port)
        log.info("Learned %s at %s on port %s" % (ip, mac, port))

        # Route IP packets for this host: rewrite the Ethernet header so the
        # packet looks like it came from the router and is addressed to the
        # host's real MAC, then send it out the host's port. Priority 100 is
        # below the hnotrust1 drop rules, so the firewall still wins.
        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_dst = ip
        msg.actions.append(of.ofp_action_dl_addr.set_src(ROUTER_MAC))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(mac))
        msg.actions.append(of.ofp_action_output(port=port))
        self.connection.send(msg)

    def send_arp_reply(self, request, port):
        """
        Answer an ARP request with the router's MAC, out the port it came in.
        """
        reply = arp()
        reply.opcode = arp.REPLY
        reply.hwsrc = ROUTER_MAC
        reply.protosrc = request.protodst  # "I am the IP you asked about"
        reply.hwdst = request.hwsrc
        reply.protodst = request.protosrc

        frame = ethernet(type=ethernet.ARP_TYPE, src=ROUTER_MAC, dst=request.hwsrc)
        frame.payload = reply
        self.resend_packet(frame.pack(), port)


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part4Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
