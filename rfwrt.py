"""
   RFW for OpenWRT, OpenFlow 1.0
"""

import json
import struct

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.ofproto import ofproto_v1_0
from ryu.lib import addrconv
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


from webob.response import Response
from ryu.app.wsgi import (
    WSGIApplication, ControllerBase,
    )


PRIO_DEFAULT_FLOW = 0x0001
PRIO_BLOCK_FLOW   = 0x0010

def ipv4_text_to_int(ip_text):
    if ip_text == 0:
        return ip_text
    #assert isinstance(ip_text, str)
    return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]


class RFWRT (app_manager.RyuApp) :

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _CONTEXTS = {
        'dpset' : dpset.DPSet,
        'wsgi' : WSGIApplication,
        }

    def __init__ (self, *args, **kwargs) :
        super (RFWRT, self).__init__ (*args, **kwargs)
        self.fdb = {} # mac -> portnum
        self.blocked_ip = set () # block IP address
        self.wsgi = kwargs['wsgi']
        self.datapath = None  # dp_handler will overwrite
        self.portlist = [] # port list

        # load Restful API
        mapper = self.wsgi.mapper
        self.wsgi.registory['RestApi'] = { 'rfwrt' : self }

        mapper.connect ('add_blocking_ip', "/add_blocking/{ipaddr}",
                        controller = RestApi,
                        action = 'add_blocking_ip',
                        conditions = dict (method = ['PUT']))
        mapper.connect ('del_blocking_ip', "/del_blocking/{ipaddr}",
                        controller = RestApi,
                        action = 'del_blocking_ip',
                        conditions = dict (method = ['PUT']))
        return


    def blocking_ip_exist (self, ipaddr) :

        if ipaddr in self.blocked_ip :
            return True
        return False


    def add_blocking_ip (self, ipaddr) :
        
        if not self.datapath :
            return False

        self.blocked_ip.add (ipaddr)

        datapath = self.datapath

        for port in self.portlist :

            match = datapath.ofproto_parser.OFPMatch (
                in_port = port,
                dl_type = ether_types.ETH_TYPE_IP,
                nw_src = ipv4_text_to_int (ipaddr))
            self.add_flow (datapath, match, [], priority = PRIO_BLOCK_FLOW)

            match = datapath.ofproto_parser.OFPMatch (
                in_port = port,
                dl_type = ether_types.ETH_TYPE_IP,
                nw_dst = ipv4_text_to_int (ipaddr))
            self.add_flow (datapath, match, [], priority = PRIO_BLOCK_FLOW)

        return


    def del_blocking_ip (self, ipaddr) :

        if not self.datapath :
            return False

        self.blocked_ip.remove (ipaddr)

        datapath = self.datapath

        for port in self.portlist :

            match = datapath.ofproto_parser.OFPMatch (
                in_port = port,
                dl_type = ether_types.ETH_TYPE_IP,
                nw_src = ipv4_text_to_int (ipaddr))
            self.del_flow (datapath, match, [])

            match = datapath.ofproto_parser.OFPMatch (
                in_port = port,
                dl_type = ether_types.ETH_TYPE_IP,
                nw_dst = ipv4_text_to_int (ipaddr))
            self.del_flow (datapath, match, [])

        return


    def add_flow (self, datapath, match, actions,
                  priority = PRIO_DEFAULT_FLOW) :

        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod (
            datapath = datapath, match = match, cookie = 0,
            command = ofproto.OFPFC_ADD, idle_timeout = 0, hard_timeout = 0,
            priority = priority, flags = ofproto.OFPFF_SEND_FLOW_REM,
            actions = actions)

        datapath.send_msg (mod)
        return


    def del_flow (self, datapath, match, actions) :

        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod (
            datapath = datapath, match = match, cookie = 0,
            command = ofproto.OFPFC_DELETE, actions = actions)

        datapath.send_msg (mod)
        return


    @set_ev_cls (ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler (self, ev) :
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet (msg.data)
        eth = pkt.get_protocol (ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP :
            return

        dst = eth.dst
        src = eth.src

        self.fdb[src] = msg.in_port

        if dst in self.fdb :
            to_port = self.fdb[dst]
        else :
            to_port = ofproto.OFPP_FLOOD

        match = datapath.ofproto_parser.OFPMatch (in_port = msg.in_port,
                                                  dl_dst = haddr_to_bin (dst))
        actions = [datapath.ofproto_parser.OFPActionOutput (to_port)]

        #print "packet in %s>%s, %d>%d" % (src, dst, msg.in_port, to_port)

        if to_port != ofproto.OFPP_FLOOD :
            self.add_flow (datapath, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER :
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut (
            datapath = datapath, buffer_id = msg.buffer_id,
            in_port = msg.in_port, actions = actions, data = data)

        datapath.send_msg (out)
        
        return


    @set_ev_cls (ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            print ("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            print ("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            print ("port modified %s", port_no)
        else:
            print ("Illeagal port state %s %s", port_no, reason)

        return

    @set_ev_cls (ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler (self, ev) :

        dpid = ev.msg.datapath.id
        print ("Switch [%d] is connected." % dpid)
        self.datapath = ev.msg.datapath
        print "and datapath is set"

        return


    @set_ev_cls (dpset.EventDP)
    def dp_handler (self, ev) :

        if not ev.enter :
            print "openflow switch [%d] left" % ev.dp.id
        else :
            print "openflow switch [%d] join, port list %s" % (
                ev.dp.id, ' '.join (map (lambda x : str (x.port_no),
                                         ev.ports)))
            self.portlist = map (lambda x: x.port_no, ev.ports)

        return


class RestApi (ControllerBase) :

    def __init__ (self, body, link, data, **config) :
        super (RestApi, self).__init__ (body, link, data, **config)
        self.rfwrt = data['rfwrt']
        return


    def add_blocking_ip (self, req, ipaddr, ** _kwargs) :

        print "add_blocking_ip %s" % ipaddr

        if self.rfwrt.blocking_ip_exist (ipaddr) :
            jsondict = { "error" : "%s already exists." % ipaddr }

        else :
            self.rfwrt.add_blocking_ip (ipaddr)
            jsondict = { "success" : "%s is added." % ipaddr }

        return Response (content_type = "application/json",
                         body = json.dumps (jsondict, indent = 4))

    def del_blocking_ip (self, req, ipaddr, ** _kwargs) :

        print "del_blocking_ip %s" % ipaddr

        if not self.rfwrt.blocking_ip_exist (ipaddr) :
            jsondict = { "error" : "%s does not exist." % ipaddr }
            return Response (content_type = "application/json",
                             body = json.dumps (jsondict, indent = 4))
        else :
            self.rfwrt.del_blocking_ip (ipaddr)
            jsondict = { "success" : "%s is deleted." % ipaddr }

        return Response (content_type = "application/json",
                         body = json.dumps (jsondict, indent = 4))