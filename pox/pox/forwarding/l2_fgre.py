from pox.core import core
from pox.lib.packet import lldp
from pox.lib.util import dpidToStr
import logging
import pox.lib.packet.ethernet as eth
import pox.openflow.libopenflow_01 as of
import sys

class Colours(object):
    """
    Helper class to colour the log messages.
    """
    GREEN = "\033[1;92m" #"\033[46m"
    BLUE = "\033[1;34m"
    ORANGE = "\033[1;33m"
    ENDC = "\033[1;0m"

    def orange(self, message):
        return self.colour(message, self.ORANGE)

    def green(self, message):
        return self.colour(message, self.GREEN)

    def blue(self, message):
        return self.colour(message, self.BLUE)
    
    def colour(self, message, colour):
        return "%s%s%s" % (colour, message, self.ENDC)


class L2FGRE(object):
    """
    Toy example of a super simple OpenFlow switch that 
    installs rules to allow communication between two hosts.
    This enables IPv4 traffic coming with a predefined VLAN
    to flow in two ways between two specific locations.
    """

    def __init__(self, reactive, *args, **kwargs):
        ## Define logger and level
        self.log = core.getLogger()
        self.log.setLevel(logging.INFO)
        self.colour = Colours()
        ## Registers every method exposed by the class
#        core.openflow.addListeners(self)
        self.reactive = reactive
        ## Registers a method based upon the 'reactive' param
        if self.reactive:
            self.ctrl_mode = "reactive"
            core.openflow.addListenerByName("PacketIn", self._handle_PacketIn)
        else:
            self.ctrl_mode = "proactive"
            core.openflow.addListenerByName("ConnectionUp", self._handle_ConnectionUp)
        self.log.info(self.colour.blue("Pre-configured toy switch for FGRE 2015 (mode=%s)." % self.ctrl_mode))
        self.log.info(self.colour.blue("Pre-configure dummy switch to use as toy example for FGRE 2015."))
        
        ## Constants section
        # Define value of protocol number assigned to IP and LLDP traffic
        self.ip_proto = 2048 #0x0800
        self.lldp_proto = 35020 #0x88cc

        # TODO: Replace by your granted VLAN
        self.vlan = 1798
    
    def __dpid_to_int(self, dpid):
        """
        Converts dpid to string (if numeric), and then
        parse it to obtain the LSB, which indicates the
        datapath number.
    
        Example:
          input   => dpid = 00-00-00-00-00-01|16
          output  => dpid = 1
        """
        if isinstance(dpid, int):
            dpid = dpidToStr(dpid)
        # (Perform operations to convert to integer)
        dpid = dpid.split("|", 1)[0]
        dpid = dpid.replace("-", "")
        dpid = int(dpid)
        return dpid
    
    def __define_rules(self, handler_type, event):
        # Retrieve dpid (switch ID)
        dpid = self.__dpid_to_int(event.dpid)
        # Retrieve port for packet on rule failure
        if handler_type == "PacketIn":
            in_port = event.port
            self.log.info(self.colour.green("Receiving packet from dpid=%s, in_port=%s" % (dpid, in_port)))
        else:
            self.log.info(self.colour.green("Detecting dpid=%s" % dpid))

        if dpid == 1:
          if handler_type == "PacketIn":
              # Forth (Verdaguer -> Rodoreda)
              if in_port == 12:
                  self.__insert_rule(event, self.vlan, in_port, 3)
              # Back (Rodoreda -> Verdaguer)
              if in_port == 3:
                  self.__insert_rule(event, self.vlan, in_port, 12)
          elif handler_type == "ConnectionUp":
             self.__insert_rule_2_ways(event, self.vlan, 3, 12)
        elif dpid == 3:
          if handler_type == "PacketIn":
              if in_port == 1:
                self.__insert_rule(event, self.vlan, in_port, 2)
              if in_port == 2:
                self.__insert_rule(event, self.vlan, in_port, 1)
          elif handler_type == "ConnectionUp":
             self.__insert_rule_2_ways(event, self.vlan, 1, 2)
        elif dpid == 2:
          if handler_type == "PacketIn":
              if in_port == 3:
                self.__insert_rule(event, self.vlan, in_port, 4)
              if in_port == 4:
                self.__insert_rule(event, self.vlan, in_port, 3)
          elif handler_type == "ConnectionUp":
             self.__insert_rule_2_ways(event, self.vlan, 3, 4)
        elif dpid == 4:
          if handler_type == "PacketIn":
              if in_port == 2:
                self.__insert_rule(event, self.vlan, in_port, 5)
              if in_port == 5:
                self.__insert_rule(event, self.vlan, in_port, 2)
          elif handler_type == "ConnectionUp":
             self.__insert_rule_2_ways(event, self.vlan, 2, 5)
        elif dpid == 5:
          if handler_type == "PacketIn":
              if in_port == 4:
                self.__insert_rule(event, self.vlan, in_port, 12)
              if in_port == 12:
                self.__insert_rule(event, self.vlan, in_port, 4)
          elif handler_type == "ConnectionUp":
             self.__insert_rule_2_ways(event, self.vlan, 4, 12)
    
    def __define_match(self, event, vlan, in_port, out_port):
        """
        Given a VLAN, input port and output port,
        generate a match and actions structure.
        """
        dpid = self.__dpid_to_int(event.dpid)
        # Note: only for reactive controller
        if out_port is None:
          out_port = event.port
        msg = of.ofp_flow_mod()
        # Match conditions (headers)
        msg.match.dl_vlan = vlan
        msg.match.in_port = in_port
        msg.match.out_port = out_port
        # Use idle and/or hard timeouts to help cleaning the table
        # Hard-timeout should be larger on ConnectionUp...
        msg.idle_timeout = 10
        msg.hard_timeout = 120
        # Define priority of rule
        msg.priority = 40
        # Action(s) to be performed on match
        msg.actions.append(of.ofp_action_output(port = out_port))
        return msg
    
    def __insert_rule(self, event, vlan, in_port, out_port):
        """
        Given an event, dpid, and a match+action structures, send 
        them to the switch in order to set up the flow entry.
        """
        dpid = self.__dpid_to_int(event.dpid)
        msg = self.__define_match(event, vlan, in_port, out_port)
        # Send flowmod
        event.connection.send(msg)
        self.log.info(self.colour.orange("Installing rule [dpid=%s]: vlan=%s, in=%s <-> out=%s" % 
            (dpid, msg.match.dl_vlan, msg.match.in_port, msg.match.out_port)))
    
    def __insert_rule_2_ways(self, event, vlan, in_port, out_port):
        """
        Invokes twice the '__insert_rule' method, 
        swapping input and output ports.
        Useful to allow faster communication from
        source to destination.
        """
        # Forth
        self.__insert_rule(event, vlan, in_port, out_port)
        # Back
        self.__insert_rule(event, vlan, out_port, in_port)
    
    def _handle_PacketIn(self, event):
        """
        Reactive behaviour for the controller.
        When a Packet-In event arrives to the controller
        as a result of unknown/non-existing actions,
        this applies a number of prefedined rules
        to ensure two-way communication between servers
        in specific locations.
        """
        packet = event.parsed
        
        # Avoid LLDP traffic
    #    if packet.next.eth_type != eth.LLDP_TYPE: 
        try:
            packet.next.eth_type
        except:
            return
    
        # Only pay attention to our tagged traffic
        if packet.next.id != self.vlan:
            return
        self.__define_rules("PacketIn", event)

    def _handle_ConnectionUp(self, event):
        """
        Proactive behaviour for the controller.
        When the connection is first established with the
        switches, this sets up the rules to be used later on.
        """
        packet = event.connection
        self.__define_rules("ConnectionUp", event)

def launch(proactive = False):
    """
    POX typical function to register listeners on events.
    Can use a 'proactive' parameter to define ctrl behaviour.
    """
    reactive = not(proactive)
    core.registerNew(L2FGRE, reactive)
