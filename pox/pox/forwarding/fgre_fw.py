# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as 
# published by the Free Software Foundation, either version 3 of the 
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/> or
# <https://www.gnu.org/licenses/lgpl-3.0.en.html>.

from pox.core import core
from pox.lib.util import dpidToStr
import pox.log.color
import pox.lib.packet.ethernet as eth
import pox.openflow.libopenflow_01 as of
import time

class FGREFirewall(object):
    """
    Toy example of a super simple OpenFlow-based firewall that
    identifies frequency of traffic from a machine and blocks it
    if it exceeds a given threshold.
    """

    def __init__(self, vlan, threshold, *args, **kwargs):
        ## Define logger (defaults to current path)
        self.log = core.getLogger()
        # Disable logger for 'packet' (TLV)
        logger = core.getLogger("packet")
        logger.propagate = False
        ## Registers every method exposed by the class
        core.openflow.addListeners(self)
        self.vlan = int(vlan)
        ## Firewall-related
        self.traffic_frequency = {}
        # Threshold time (in seconds) to determine harmful network conditions (e.g.: 0.2)
        self.threshold = float(threshold)
        # Time (in seconds) to maintain the DROP rules for the network traffic deemed harmful
        self.idle_drop_time = 30
        self.hard_drop_time = 30
        ## Constants section
        # Define value of protocol number assigned to IP and LLDP traffic
        self.ip_proto = 2048 #0x0800
        self.lldp_proto = 35020 #0x88cc
        self.max_priority = 65535
        self.log.info("Toy firewall for FGRE 2015 (seconds threshold=%s, vlan=%s)." % (self.threshold, self.vlan))
    
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
    
    def __identify_harmful_traffic(self, dpid, in_port):
        """
        Identifies network conditions. A (dpid, in_port)
        may be marked as a possible source of harmful
        traffic and consequently blocked for a while.
        """
        harmful_traffic = False
        current_time = time.time()
        try:
            last_time = self.traffic_frequency.get(dpid).get(in_port).get("last_time")
            # Increasing margin for the detection of potential malicious behaviour
            if (current_time - last_time) <= 4 * self.threshold:
                harmful_traffic = True
        except Exception as e:
            # When a PacketIn condition appears for the 1st time, create its structure
            self.traffic_frequency[dpid] = {in_port: {}}
        return harmful_traffic
    
    def __register_frequency(self, dpid, in_port):
        """
        Keeps up-to-date the 'traffic_frequency' structure
        with the number and last time for a received packet
        from a given dpid and input port
        """
        # If structure not already initialised, then add keys
        try:
            self.traffic_frequency.get(dpid).get(in_port)
        except:
            self.traffic_frequency[dpid] = {in_port: {}}
        # Attempt to recover count of packets, if it was already present
        try:
            count = self.traffic_frequency.get(dpid).get(in_port).get("count")
            self.traffic_frequency[dpid][in_port].update({"last_time": time.time(), "count": count+1})
        except:
            self.traffic_frequency[dpid][in_port].update({"last_time": time.time(), "count": 1})
    
    def __define_rules(self, event):
        # Retrieve dpid (switch ID) and in_port from PacketIn event message
        dpid = self.__dpid_to_int(event.dpid)
        in_port = event.port
        
        # Retrieve port for packet on rule failure
        self.log.info("Receiving packet from dpid=%s, in_port=%s" % (dpid, in_port))
        
        is_harmful = self.__identify_harmful_traffic(dpid, in_port)
        self.__register_frequency(dpid, in_port)
        
        # If traffic is deemed harmful, insert DROP rule
        # Otherwise, send a packet-out to proceed
        if is_harmful:
            self.__insert_rule_2_ways(event, self.vlan, in_port)
        else:
            if dpid == 1:
                # Forth (Verdaguer -> Rodoreda)
                if in_port == 12:
                    self.__send_packetout(event, self.vlan, in_port, 3)
                # Back (Rodoreda -> Verdaguer)
                if in_port == 3:
                    self.__send_packetout(event, self.vlan, in_port, 12)
            elif dpid == 3:
                if in_port == 1:
                    self.__send_packetout(event, self.vlan, in_port, 2)
                if in_port == 2:
                    self.__send_packetout(event, self.vlan, in_port, 1)
            elif dpid == 2:
                if in_port == 3:
                    self.__send_packetout(event, self.vlan, in_port, 4)
                if in_port == 4:
                    self.__send_packetout(event, self.vlan, in_port, 3)
            elif dpid == 4:
                if in_port == 2:
                    self.__send_packetout(event, self.vlan, in_port, 5)
                if in_port == 5:
                    self.__send_packetout(event, self.vlan, in_port, 2)
            elif dpid == 5:
                if in_port == 4:
                    self.__send_packetout(event, self.vlan, in_port, 12)
                if in_port == 12:
                    self.__send_packetout(event, self.vlan, in_port, 4)
    
    def __define_packetout(self, buffer_id, raw_data, vlan, in_port, out_port):
        #Sends a packet out of the specified switch port.
        msg = of.ofp_packet_out()
        #msg.buffer_id = buffer_id
        msg.in_port = in_port
        msg.vlan = vlan
        msg.data = raw_data
        # Add an action to send to the specified port
        action = of.ofp_action_output(port = out_port)
        msg.actions.append(action)
        return msg
    
    def __define_match(self, event, vlan, in_port, out_port=None):
        """
        Given a VLAN, input port and output port,
        generate a match and actions structure.
        """
        dpid = self.__dpid_to_int(event.dpid)
        msg = of.ofp_flow_mod()
        # No out_port => no action => equivalent to DROP rule
        if out_port is not None:
            # Action(s) to be performed on match
            msg.actions.append(of.ofp_action_output(port = out_port))
        # Match conditions (headers)
        msg.match.dl_vlan = vlan
        msg.match.in_port = in_port
        # Use idle and/or hard timeouts to help cleaning the table
        msg.idle_timeout = self.idle_drop_time
        msg.hard_timeout = self.hard_drop_time
        # Define priority of rule: no actions -> highest priority
        if len(msg.actions) == 0:
            msg.priority = self.max_priority
        else:
            msg.priority = 40
        return msg

    def __insert_rule(self, event, vlan, in_port, out_port=None):
        """
        Given an event, dpid, and a match+action structures, send 
        them to the switch in order to set up the flow entry.
        """
        dpid = self.__dpid_to_int(event.dpid)
        msg = self.__define_match(event, vlan, in_port, out_port)
        # Send flowmod
        event.connection.send(msg)
        if out_port is None:
            self.log.info("Installing DROP rule [dpid=%s]: vlan=%s, in=%s" % 
                (dpid, msg.match.dl_vlan, msg.match.in_port))
        else:
            self.log.info("Installing DROP rule [dpid=%s]: vlan=%s, in=%s <-> out=%s" % 
                (dpid, msg.match.dl_vlan, msg.match.in_port, msg.match.out_port))
    
    def __insert_rule_2_ways(self, event, vlan, in_port, out_port=None):
        """
        Invokes twice the '__insert_rule' method, 
        swapping input and output ports.
        Useful to allow faster communication from
        source to destination.
        """
        if out_port is None:
            self.__insert_rule(event, vlan, in_port)
        else:
            # Forth
            self.__insert_rule(event, vlan, in_port, out_port)
            # Back
            self.__insert_rule(event, vlan, out_port, in_port)
    
    def __send_packetout(self, event, vlan, in_port, out_port):
        """
        Given an event, dpid, and a match+action structures, send 
        them to the switch in order to set up the flow entry.
        """
        dpid = self.__dpid_to_int(event.dpid)
        msg = self.__define_packetout(event.ofp.buffer_id, event.ofp.data, vlan, event.ofp.in_port, out_port)
        # Send packet-out
        event.connection.send(msg)
        self.log.debug("Sending packet-out [dpid=%s]: vlan=%s, in=%s <-> out=%s" %
            (dpid, vlan, in_port, out_port))
    
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
        try:
            #if packet.next.eth_type != eth.LLDP_TYPE: 
            # LLDP packets fail on accessing this field
            packet.next.eth_type
        except:
            return
    
        # Only pay attention to our tagged traffic
        if packet.next.id != self.vlan:
            return
        self.__define_rules(event)

def launch(vlan, threshold):
    """
    POX typical function to register listeners on events.
    Arguments:
        Threshold: seconds allowed during output traffic from a machine.
    """
    # Launch log colour app
    pox.log.color.launch()
    pox.log.launch(format="[@@@bold@@@level%(name)-22s@@@reset] " +
                        "@@@bold%(message)s@@@normal")
    core.registerNew(FGREFirewall, vlan, threshold)
