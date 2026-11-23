# Part 2 of UWCSE's Project 3
#
# based on Lab 4 from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt

log = core.getLogger()


class Firewall(object):
    """
    A Firewall object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # Install the firewall rules once, when the switch connects.
        # Higher priority wins, so the ICMP rule beats the IPv4 drop rule.
        self._install_rule(
            priority=30,
            match=of.ofp_match(dl_type=pkt.ethernet.IP_TYPE,
                               nw_proto=pkt.ipv4.ICMP_PROTOCOL),
            flood=True,
        )
        self._install_rule(
            priority=20,
            match=of.ofp_match(dl_type=pkt.ethernet.ARP_TYPE),
            flood=True,
        )
        self._install_rule(
            priority=10,
            match=of.ofp_match(dl_type=pkt.ethernet.IP_TYPE),
            flood=False,
        )

    def _install_rule(self, priority, match, flood):
        """
        Send a flow rule to the switch. A rule with no actions drops
        every packet it matches.
        """
        msg = of.ofp_flow_mod()
        msg.priority = priority
        msg.match = match
        if flood:
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
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
        print("Unhandled packet :" + str(packet.dump()))


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Firewall(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
