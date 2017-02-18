#!/usr/bin/env python
import sys
import time
import math
import json
import random
from collections import defaultdict
import controller.framework.fxlib as fxlib
from controller.framework.ControllerModule import ControllerModule
from controller.framework.CFx import CFX


class BaseTopologyManager(ControllerModule,CFX):

    def __init__(self, CFxHandle, paramDict, ModuleName):

        super(BaseTopologyManager, self).__init__(CFxHandle, paramDict, ModuleName)
        self.CFxHandle = CFxHandle
        self.CMConfig = paramDict
        #self.ipop_state = None
        self.interval_counter = 0
        self.cv_interval = 5
        self.use_visualizer = False
        # need this to query for peer state since it is no longer maintained 
        # by tincan.
        #self.peer_uids = defaultdict(int)
        #self.peer_uids = {}
        self.ipop_interface_details={}
        self.sendcount = ""
        self.receivecount = ""
        #self.uid = ""  will get from CFx self.Config which has been inherited by Base Topology Manager
        #self.ip4 = ""
        #self.ipv6= ""
        #self.cas = {}
        #self.mac = {}

        # peers (linked nodes)
        #self.peers = {}

        # links:
        #   self.links["successor"] = { uid: None }
        #   self.links["chord"]     = { uid: {"log_uid": log_uid, "ttl": ttl} }
        #   self.links["on_demand"] = { uid: {"ttl": ttl, "rate": rate} }
        #self.links = {
            #"successor": {}, "chord": {}, "on_demand": {}
        #}

        #self.log_chords = []

        self.max_num_links = self.CMConfig["num_successors"] + \
                             self.CMConfig["num_chords"] + \
                             self.CMConfig["num_on_demand"] + \
                             self.CMConfig["num_inbound"]
        self.maxretries = self.CMConfig["max_conn_retries"]
        # discovered nodes
        #   self.discovered_nodes is the list of nodes used by the successors policy
        #   self.discovered_nodes_srv is the list of nodes obtained from peer_state
        #       notifications
        #self.discovered_nodes = []
        #self.discovered_nodes_srv = []

        # p2p overlay state
        #self.p2p_state = "started"

        # address mapping


        # populate uid_ip4_table and ip4_uid_table with all UID and IPv4
        # mappings within the /16 subnet
        self.tincanparams = self.CFxHandle.queryParam("Tincan")
        for k in range(len(self.tincanparams["vnets"])):
            '''
            uid_ip4_table = {}
            ip4_uid_table = {}
            parts = cfx["vnets"][k]["ip4"]                                  #parts = self.CFxHandle.queryParam("ip4").split(".")
            ip_prefix = parts[0] + "." + parts[1] + "."
            for i in range(0, 255):
                for j in range(0, 255):
                    ip4 = ip_prefix + str(i) + "." + str(j)
                    uid = fxlib.gen_uid(ip4)
                    uid_ip4_table[uid] = ip4
                    ip4_uid_table[ip4] = uid
            '''
            interface_name= self.tincanparams["vnets"][k]["ipoptap_name"]
            self.ipop_interface_details[interface_name]                         = {}
            self.ipop_interface_details[interface_name]["index"]                = k
            self.ipop_interface_details[interface_name]["p2p_state"]            = "started"
            self.ipop_interface_details[interface_name]["discovered_nodes"]     = []
            self.ipop_interface_details[interface_name]["discovered_nodes_srv"] = []
            self.ipop_interface_details[interface_name]["peer_uids"]            = {}
            self.ipop_interface_details[interface_name]["cas"]                  = ""
            self.ipop_interface_details[interface_name]["mac"]                  = ""
            self.ipop_interface_details[interface_name]["links"]                = { "successor": {}, "chord": {}, "on_demand": {}}
            self.ipop_interface_details[interface_name]["log_chords"]           = []
            self.ipop_interface_details[interface_name]["peers"]                = {}
            self.ipop_interface_details[interface_name]["ipop_state"]           = None
            self.ipop_interface_details[interface_name]["uid_mac_table"]        = {}
            self.ipop_interface_details[interface_name]["mac_uid_table"]        = {}


        if 'use_central_visualizer' in self.CMConfig:
            self.use_visualizer = self.CMConfig["use_central_visualizer"]
        if "interval_central_visualizer" in self.CMConfig:
            self.cv_interval = self.CMConfig["interval_central_visualizer"]

    def initialize(self):
        self.registerCBT('Logger', 'info', "{0} Loaded".format(self.ModuleName))

    ############################################################################
    # send message functions                                                   #
    ############################################################################

    # send message (through XMPP service)
    #   - msg_type = message type attribute
    #   - uid      = UID of the destination node
    #   - msg      = message
    def send_msg_srv(self, msg_type, uid, msg,interface_name):
        cbtdata = {"method": msg_type, "overlay_id": 0, "uid": uid, "data": msg,"interface_name":interface_name,\
                   "interface_index":self.ipop_interface_details[interface_name]["index"]} #TODO overlay_id
        self.registerCBT('XmppClient', 'DO_SEND_MSG', cbtdata)

    # send message (through ICC)
    #   - uid = UID of the destination peer (a tincan link must exist)
    #   - msg = message
    def send_msg_icc(self, uid, msg,interface_name):
        if uid in self.ipop_interface_details[interface_name]["peers"]:
            if "ip6" in self.ipop_interface_details[interface_name]["peers"][uid]:
                cbtdata = {
                    "src_uid": self.tincanparams["vnets"][self.ipop_interface_details[interface_name]["index"]]["uid"],
                    "dst_uid": uid,
                    "msg": msg,
                    "interface_name":interface_name
                }
                print("ICC Message overlay"+str(cbtdata))
                self.registerCBT('TincanSender', 'DO_SEND_ICC_MSG', cbtdata)

    ############################################################################
    # connectivity functions                                                   #
    ############################################################################

    # request connection
    #   send a connection request
    #   - con_type = {successor, chord, on_demand}
    #   - uid      = UID of the target node
    def request_connection(self, con_type, uid,interface_name):
        index = self.ipop_interface_details[interface_name]["index"]
        # send connection request to larger nodes
        data = {
            "fpr": self.ipop_interface_details[interface_name]["ipop_state"]["_fpr"],
            "ip4": self.tincanparams["vnets"][index]["ip4"],
            "ip6": self.tincanparams["vnets"][index]["ip6"],
            "mac": self.ipop_interface_details[interface_name]["mac"],
            "con_type": con_type
        }
        try:
            self.send_msg_srv("con_req", uid, json.dumps(data),interface_name)
        except:
            self.registerCBT('Logger', 'info', "Exception in send_msg_srv con_req") 

        log = "sent con_req ({0}): {1}".format(con_type, uid)
        self.registerCBT('Logger', 'debug', log)

    # respond connection
    #   create connection and return a connection acknowledgement and response
    #   - uid  = UID of the target node
    #   - data = information necessary to establish a link
    def respond_connection(self, con_type, uid, data,interface_name):

        #changes done as part of release 17.0
        #self.create_connection(uid, data)
        index = self.ipop_interface_details[interface_name]["index"]
        # send con_ack message
        data = {
            "fpr": self.ipop_interface_details[interface_name]["ipop_state"]["_fpr"],
            "ip4": self.tincanparams["vnets"][index]["ip4"],
            "ip6": self.tincanparams["vnets"][index]["ip6"],
            "mac": self.ipop_interface_details[interface_name]["mac"],
            "cas": data["cas"],
            "con_type": con_type
        }

        self.send_msg_srv("con_ack", uid, json.dumps(data),interface_name)
        log = "sent con_ack to {0}".format(uid)
        self.registerCBT('Logger','debug', log)

    # create connection
    #   establish a tincan link
    #   - uid  = UID of the target node
    #   - data = information necessary to establish a link
    def create_connection(self, uid, data,interface_name):
        interface_details = self.ipop_interface_details[interface_name]
        # FIXME check_collision was removed
        #fpr_len = len(self.ipop_state["_fpr"])
        fpr = data["fpr"]                                           #fpr = data[:fpr_len]
        nid = 0 # need this to make tincan fwd con_resp to controller.
        sec = self.CMConfig["sec"]
        cas = data["cas"]                                           #cas = data[fpr_len + 1:]
        index = interface_details["index"]
        ip4 = self.tincanparams["vnets"][index]["uid_ip4_table"][uid]
        ip6 = self.tincanparams["vnets"][index]["ip6"]

        con_dict = {'uid': uid, 'fpr': fpr, 'nid': nid, 'sec': sec, 'cas': cas,
                    "ip4": ip4, "mac" : data["mac"], "con_type": data["con_type"],"interface_name":interface_name,"ip6":ip6}    #con_dict = {'uid': uid, 'fpr': data, 'nid': nid, 'sec': sec, 'cas': cas}
        self.registerCBT('LinkManager', 'CREATE_LINK', con_dict)
        # Add uid to list for whom connection has been attempted.
        self.ipop_interface_details[interface_name]["peer_uids"][uid] = 1
        '''
        cbtdata = {"uid": uid, "ip4": ip4}
        self.registerCBT('TincanSender', 'DO_SET_REMOTE_IP', cbtdata)
        '''
    def linked(self, uid,interface_name):
        peers = self.ipop_interface_details[interface_name]["peers"]
        if uid in peers.keys():#if uid in self.peers:
            if peers[uid]["con_status"] == "online" or peers[uid]["status"] == "online":
                return True
        return False

    # remove connection
    #   remove a link by peer UID
    #   - uid = UID of the peer
    def remove_connection(self, uid,interface_name):
        if uid in self.ipop_interface_details[interface_name]["peers"]:
            msg = {"interface_name": interface_name, "uid": uid}
            self.registerCBT('TincanSender', 'DO_TRIM_LINK', msg)
            self.ipop_interface_details[interface_name]["peers"].pop(uid)

            for con_type in ["successor", "chord", "on_demand"]:
                if uid in self.ipop_interface_details[interface_name]["links"][con_type].keys():
                    self.ipop_interface_details[interface_name]["links"][con_type].pop(uid)

            log = "removed connection: {0}".format(uid)
            self.registerCBT('Logger', 'info', log)


    # clean connections
    #   remove peers with expired time-to-live attributes
    def clean_connections(self,interface_name):
        # time-to-live attribute indicative of an offline link
        for uid in list(self.ipop_interface_details[interface_name]["peers"].keys()):
            if time.time() > self.ipop_interface_details[interface_name]["peers"][uid]["ttl"]:
                self.remove_connection(uid,interface_name)

        # periodically call policy for link removal
        self.clean_chord(interface_name)
        self.clean_on_demand(interface_name)

    ############################################################################
    # add/remove link functions                                                #
    ############################################################################

    # add outbound link
    def add_outbound_link(self, con_type, uid, attributes,interface_name):
        interface_details = self.ipop_interface_details[interface_name]
        # add peer to link type
        interface_details["links"][con_type][uid] = attributes

        self.registerCBT('Logger', 'info', "peer::" + str(interface_details["peers"]))
        # peer is not in the peers list
        if uid not in interface_details["peers"].keys():
            index = interface_details["index"]
            # add peer to peers list
            interface_details["peers"][uid] = {
                "uid": uid  ,
                "ttl": time.time() + self.CMConfig["ttl_link_initial"],
                "con_status": "sent_con_req"
            }
            # connection request
            try:
                self.request_connection(con_type, uid,interface_name)
            except Exception as err:
                self.registerCBT('Logger', 'error', "Exception in request_connection. Exception::"+ str(err))

    # add inbound link
    def add_inbound_link(self, con_type, uid, fpr,interface_name):
        # recvd con_req and sender is in peers_list - uncommon case
        peer  = self.ipop_interface_details[interface_name]["peers"]
        index = self.ipop_interface_details[interface_name]["index"]
        if (uid in peer.keys()):
            log_msg = "AIL: Recvd con_req for peer in list from {0} status {1}".format(uid,peer[uid]["con_status"])
            self.registerCBT('Logger','info',log_msg)
            # if node has received con_req, re-respond (in case it was lost)
            if (peer[uid]["con_status"] == "recv_con_req"):
                log_msg = "AIL: Resending respond_connection to {0}".format(uid)
                self.registerCBT('Logger','info',log_msg)
                self.respond_connection(con_type, uid, fpr,interface_name)
                return

            # else if node has sent con_request concurrently
            elif (peer[uid]["con_status"] == "sent_con_req"):
                # peer with smaller UID sends a response 
                if (self.tincanparams["vnets"][index]["uid"] > uid):
                    log_msg = "AIL: LargerUID respond_connection to {0}".format(uid)
                    self.registerCBT('Logger','info',log_msg)
                    peer[uid] = {
                        "uid": uid,
                        "ttl": time.time() + self.CMConfig["ttl_link_initial"],
                        "con_status": "conc_sent_response"
                    }
                    self.respond_connection(con_type, uid, fpr,interface_name)
                # peer with larger UID ignores 
                else:
                    log_msg = "AIL: SmallerUID ignores from {0}".format(uid)
                    self.registerCBT('Logger','info',log_msg)
                    peer[uid] = {
                        "uid": uid,
                        "ttl": time.time() + self.CMConfig["ttl_link_initial"],
                        "con_status": "conc_no_response"
                    }
                return
            elif peer[uid]["con_status"] == "offline":
                if "connretrycount" not in peer[uid].keys():
                    peer[uid]["connretrycount"] = 0
                else:
                    if peer[uid]["connretrycount"]< self.maxretries:
                        peer[uid]["connretrycount"] += 1
                    else:
                        log_msg = "AIL: Giving up after max conn retries, remove_connection from {0}".format(uid)
                        self.registerCBT('Logger', 'warning', log_msg)
                        self.remove_connection(uid, interface_name)
            # if node was in any other state:
            # replied or ignored a concurrent send request:
            #    conc_no_response, conc_sent_response
            # or if status is online or offline, 
            # remove link and wait to try again
            else:
                if peer[uid]["con_status"]!="unknown":
                    log_msg = "AIL: Giving up, remove_connection from {0}".format(uid)
                    self.registerCBT('Logger','info',log_msg)
                    self.remove_connection(uid,interface_name)

        # recvd con_req and sender is not in peers list - common case
        else:
            # add peer to peers list and set status as having received and
            # responded to con_req
            log_msg = "AIL: Recvd con_req for peer not in list {0}".format(uid)
            self.registerCBT('Logger','info',log_msg)
            peer[uid] = {
                "uid": uid,
                "ttl": time.time() + self.CMConfig["ttl_link_initial"],
                "con_status": "recv_con_req"
            }

            # connection response
            self.respond_connection(con_type, uid, fpr,interface_name)
            

    # remove link
    def remove_link(self, con_type, uid,interface_name):

        # remove peer from link type
        if uid in self.ipop_interface_details[interface_name]["links"][con_type].keys():
            self.ipop_interface_details[interface_name]["links"][con_type].pop(uid)

        # this peer does not have any outbound links
        if uid not in (list(self.ipop_interface_details[interface_name]["links"]["successor"].keys()) + \
                       list(self.ipop_interface_details[interface_name]["links"]["chord"].keys()) + \
                       list(self.ipop_interface_details[interface_name]["links"]["on_demand"].keys())):

            # remove connection
            self.remove_connection(uid,interface_name)

    ############################################################################
    # packet forwarding policy                                                 #
    ############################################################################

    # closer function
    #   tests if uid is successively closer to uid_B than uid_A
    def closer(self, uid_A, uid, uid_B):
        if (uid_A < uid_B) and ((uid_A < uid) and (uid <= uid_B)):
            return True  #0---A===B---N
        elif (uid_A > uid_B) and ((uid_A < uid) or (uid <= uid_B)):
            return True  #0===B---A===N
        return False

    # forward packet
    #   forward a packet across ICC
    #   - fwd_type = {
    #       exact   = intended specifically to the destination node,
    #       closest = intended to the node closest to the designated node
    #     }
    #   - dst_uid  = UID of the destination or designated node
    #   - msg      = message in transit
    #   returns true if this packet is intended for the calling node
    def forward_msg(self, fwd_type, dst_uid, msg,interface_name):

        # find peer that is successively closest to and less-than-or-equal-to
        # the designated UID
        nxt_uid = ""
        interface_details = self.ipop_interface_details[interface_name]
        index = interface_details["index"]
        uid = self.tincanparams["vnets"][index]["uid"]

        for peer in interface_details["peers"].keys():
            if self.linked(peer,interface_name):
                if self.closer(uid, peer, dst_uid):
                    nxt_uid = peer

        # packet is intended specifically to the destination node
        if fwd_type == "exact":
            print("exact",nxt_uid, uid,dst_uid)
            # this is the destination uid
            if dst_uid == uid:#if self.uid == dst_uid:
                self.send_msg_icc(nxt_uid, msg, interface_name)
                return True

            # this is the closest node but not the destination; drop packet
            elif nxt_uid == uid:#elif self.uid == nxt_uid:
                return False

        # packet is intended to the node closest to the designated node
        elif fwd_type == "closest":
            print(nxt_uid,uid)            # this is the destination uid or the node closest to it
            if nxt_uid == uid:#if self.uid == nxt_uid:
                self.send_msg_icc(nxt_uid, msg, interface_name)
                return True

        # there is a closer node; forward packet to the next node
        self.send_msg_icc(nxt_uid, msg,interface_name)
        return False

    ############################################################################
    # successors policy                                                        #
    ############################################################################
    # [1] A discovers nodes in the network
    #     A requests to link to the closest successive node B as A's successor
    # [2] B accepts A's link request, with A as B's inbound link
    #     B responds to link to A
    # [3] A and B are connected
    # [*] the link is terminated when A discovers and links to closer successive
    #     nodes, or the link disconnects
    # [*] A periodically advertises its peer list to its peers to help them
    #     discover nodes

    def add_successors(self,interface_name):
        # sort nodes into rotary, unique list with respect to this UID
        interface_details = self.ipop_interface_details[interface_name]
        index = interface_details["index"]
        uid = self.tincanparams["vnets"][index]["uid"]
        nodes = sorted(set(list(interface_details["links"]["successor"].keys()) + interface_details["discovered_nodes"]))
        self.registerCBT('Logger', 'info', "Nodes:" + str(nodes))
        if uid in nodes:
            nodes.remove(uid)
        if max([uid] + nodes) != uid:
            while nodes[0] < uid:
                nodes.append(nodes.pop(0))
            self.registerCBT('Logger', 'info', "Nodes:" + str(nodes))
        # link to the closest <num_successors> nodes (if not already linked)
        for node in nodes[0:min(len(nodes), self.CMConfig["num_successors"])]:
            self.registerCBT('Logger', 'info', "Successors:" + str(interface_details["links"]["successor"]))
            if node not in interface_details["links"]["successor"].keys():
                try:
                    self.add_outbound_link("successor", node, None,interface_name)
                except Exception as err:
                   self.registerCBT('Logger', 'error', "Exception in add_outbound_link. Exception::"+str(err))

        # reset list of discovered nodes
        # interface_details["discovered_nodes"]=[]                   #self.discovered_nodes[:]

    def remove_successors(self,interface_name):

        # sort nodes into rotary, unique list with respect to this UID
        interface_details = self.ipop_interface_details[interface_name]
        uid = self.tincanparams["vnets"][interface_details["index"]]["uid"]
        successors = sorted(interface_details["links"]["successor"].keys())
        if max([uid] + successors) != uid:
            while successors[0] < uid:
                successors.append(successors.pop(0))

        # remove all linked successors not within the closest <num_successors> linked nodes
        # remove all unlinked successors not within the closest <num_successors> nodes
        num_linked_successors = 0
        for successor in successors:
            if self.linked(successor,interface_name):
                num_linked_successors += 1

                # remove excess successors
                if num_linked_successors > self.CMConfig["num_successors"]:
                    self.remove_link("successor", successor,interface_name)

    def advertise(self,interface_name):
        # create list of linked peers
        peer_list = []
        for peer in self.ipop_interface_details[interface_name]["peers"].keys():
            if self.linked(peer,interface_name):
                peer_list.append(peer)

        # send peer list advertisement to all peers
        new_msg = {
            "msg_type": "advertise",
            "src_uid": self.tincanparams["vnets"][self.ipop_interface_details[interface_name]["index"]]["uid"],
            "peer_list": peer_list
        }

        for peer in (self.ipop_interface_details[interface_name]["peers"]).keys():
            if self.linked(peer,interface_name):
                self.send_msg_icc(peer, new_msg,interface_name)

    ############################################################################
    # chords policy                                                            #
    ############################################################################
    # [1] A forwards a headless find_chord message approximated by a designated UID
    # [2] B discovers that it is the closest node to the designated UID
    #     B responds with a found_chord message to A
    # [3] A requests to link to B as A's chord
    # [4] B accepts A's link request, with A as B's inbound link
    #     B responds to link to A
    # [5] A and B are connected
    # [*] the link is terminated when the chord time-to-live attribute expires and
    #     a better chord was found or the link disconnects

    def find_chords(self,interface_name):

        # find chords closest to the approximate logarithmic nodes
        interface_details = self.ipop_interface_details[interface_name]
        index  = interface_details["index"]
        if len(interface_details["log_chords"]) == 0:
            for i in reversed(range(self.CMConfig["num_chords"])):
                log_num = (int(self.tincanparams["vnets"][index]["uid"], 16) + int(math.pow(2, 160-1-i))) % int(math.pow(2, 160))
                log_uid = "{0:040x}".format(log_num)
                interface_details["log_chords"].append(log_uid)

        # determine list of designated UIDs
        log_chords = interface_details["log_chords"]
        for chord in interface_details["links"]["chord"].values():
            if chord["log_uid"] in log_chords:
                log_chords.remove(chord["log_uid"])

        # forward find_chord messages to the nodes closest to the designated UID
        for log_uid in log_chords:

            # forward find_chord message
            new_msg = {
                "msg_type": "find_chord",
                "src_uid": self.tincanparams["vnets"][index]["uid"],
                "dst_uid": log_uid,
                "log_uid": log_uid
            }

            self.forward_msg("closest", log_uid, new_msg,interface_name)

    def add_chord(self, uid, log_uid,interface_name):

        # if a chord associated with log_uid already exists, check if the found
        # chord is the same chord:
        # if they are the same then the chord is already the best one available
        # otherwise, remove the chord and link to the found chord

        for chord in list(self.ipop_interface_details[interface_name]["links"]["chord"].keys()):
            if self.ipop_interface_details[interface_name]["links"]["chord"][chord]["log_uid"] == log_uid:
                if chord == uid:
                    return
                else:
                    self.remove_link("chord", chord,interface_name)

        # add chord link
        attributes = {
            "log_uid": log_uid,
            "ttl": time.time() + self.CMConfig["ttl_chord"]
        }

        self.add_outbound_link("chord", uid, attributes,interface_name)

    def clean_chord(self,interface_name):
        links = self.ipop_interface_details[interface_name]["links"]
        if not links["chord"].keys():
            return


        # find chord with the oldest time-to-live attribute
        uid = min(links["chord"].keys(), key=lambda u: (links["chord"][u]["ttl"]))

        # time-to-live attribute has expired: determine if a better chord exists
        if time.time() > links["chord"][uid]["ttl"]:
            index = self.ipop_interface_details["interface_name"]["index"]
            # forward find_chord message
            new_msg = {
                "msg_type": "find_chord",
                "src_uid": self.tincanparams["vnets"][index]["uid"],
                "dst_uid": links["chord"][uid]["log_uid"],
                "log_uid": links["chord"][uid]["log_uid"]
            }

            self.forward_msg("closest", links["chord"][uid]["log_uid"], new_msg,interface_name)

            # extend time-to-live attribute
            links["chord"][uid]["ttl"] = time.time() + self.CMConfig["ttl_chord"]

    ############################################################################
    # on-demand links policy                                                   #
    ############################################################################
    # [1] A is forwarding packets to B
    #     A immediately requests to link to B, with B as A's on-demand link
    # [2] B accepts A's link request, with A as B's inbound link
    # [3] A and B are connected
    #     B responds to link to A
    # [*] the link is terminated when the transfer rate is below some threshold
    #     until the on-demand time-to-live attribute expires or the link
    #     disconnections

    def add_on_demand(self, uid,interface_name):

        if len(self.ipop_interface_details[interface_name]["links"]["on_demand"].keys()) < self.CMConfig["num_on_demand"]:

            if uid not in self.ipop_interface_details[interface_name]["links"]["on_demand"].keys():

                # add on-demand link
                attributes = {
                    "ttl": time.time() + self.CMConfig["ttl_on_demand"],
                    "rate": 0
                }
                self.add_outbound_link("on_demand", uid, attributes,interface_name)

    def clean_on_demand(self,interface_name):
        interface_details = self.ipop_interface_details[interface_name]
        for uid in list(interface_details["links"]["on_demand"].keys()):

            # rate exceeds threshold: increase time-to-live attribute
            if interface_details["links"]["on_demand"][uid]["rate"] >= self.CMConfig["threshold_on_demand"]:
                interface_details["links"]["on_demand"][uid]["ttl"] = time.time() + self.CMConfig["ttl_on_demand"]

            # rate is below theshold and the time-to-live attribute expired: remove link
            elif time.time() > interface_details["links"]["on_demand"][uid]["ttl"]:
                self.remove_link("on_demand", uid,interface_name)

    ############################################################################
    # inbound links policy                                                     #
    ############################################################################

    def add_inbound(self, con_type, uid, fpr,interface_name):

        if con_type == "successor":
            self.add_inbound_link(con_type, uid, fpr,interface_name)

        elif con_type in ["chord", "on_demand"]:
            if len(self.ipop_interface_details[interface_name]["peers"].keys()) < self.max_num_links:
                self.add_inbound_link(con_type, uid, fpr,interface_name)

    ############################################################################
    # service notifications                                                    #
    ############################################################################

    def processCBT(self, cbt):

        # tincan control messages
        if cbt.action == "TINCAN_CONTROL":
            msg = cbt.data
            msg_type = msg.get("type", None)
            interface_name  = msg["interface_name"]
            interface_details = self.ipop_interface_details[interface_name]
            # update local state
            if msg_type == "local_state":
                interface_details["ipop_state"] = msg
                #self.uid = msg["_uid"]
                #self.ip4 = msg["_ip4"]
                #self.ip6 = msg["_ip6"]
                interface_details["mac"] = msg["mac"]
                interface_details["mac_uid_table"][msg["mac"]] = msg["_uid"]

            # update peer list
            elif msg_type == "peer_state":
                interface_details["mac_uid_table"][msg["mac"]] = msg["uid"]
                if msg["uid"] in interface_details["peers"]:
                    # preserve ttl and con_status attributes
                    ttl = interface_details["peers"][msg["uid"]]["ttl"]
                    con_status = interface_details["peers"][msg["uid"]]["con_status"]

                    # update ttl attribute
                    if "online" == msg["status"]:
                        ttl = time.time() + self.CMConfig["ttl_link_pulse"]

                    self.registerCBT('Multicast', 'PeerConnectionDetails', msg)

                    # update peer state
                    interface_details["peers"][msg["uid"]]                 = msg
                    interface_details["peers"][msg["uid"]]["ttl"]          = ttl
                    #self.peers[msg["uid"]]["con_status"] = con_status
                    interface_details["peers"][msg["uid"]]["con_status"]   = msg["status"]

                    if msg["uid"] in interface_details["links"]["on_demand"].keys():
                        if "stats" in msg:
                            interface_details["links"]["on_demand"][msg["uid"]]["rate"] = msg["stats"][0]["sent_bytes_second"]


                # handle connection response
            elif msg_type == "con_resp":
                #fpr_len = len(self.ipop_state["_fpr"])
                #my_fpr = msg["data"][:fpr_len]
                #my_cas = msg["data"][fpr_len + 1:]
                index = interface_details["index"]
                data = {
                    "uid"  : self.tincanparams["vnets"][index]["uid"],
                    "fpr"  : interface_details["ipop_state"]["_fpr"],
                    "ip4"  : interface_details["ipop_state"]["_ip4"],
                    "ip6"  : interface_details["ipop_state"]["_ip6"],
                    "cas"  : interface_details["cas"],
                    "con_type" : msg["data"]["con_type"]
                }
                target_uid = msg["uid"]
                self.send_msg_srv("con_resp",target_uid,str(data),interface_name)
                log = "recv con_resp from Tincan for {0}".format(msg["uid"])
                self.registerCBT('Logger', 'info', log)           
                              
                '''self.create_connection(msg["uid"], msg["data"])

                log = "recv con_resp: {0}".format(msg["uid"])
                self.registerCBT('Logger', 'debug', log)'''

            elif msg_type == "con_ack":
                self.registerCBT('Logger', 'debug', "Received CAS from Tincan for UID {0}".format(msg["uid"]))
                interface_details["ipop_state"]["cas"] = msg["data"]["cas"]
                self.add_inbound(msg["data"]["con_type"], msg["uid"],msg["data"],interface_name)
                interface_details["peer_uids"][msg["uid"]] = 1


            elif msg_type == "con_req":
                self.registerCBT('Logger', 'info', "Received connection request from Multicast")
                self.request_connection(msg["conn_type"],msg["uid"],interface_name)


        # handle CBT's from XmppClient
        elif cbt.action == "XMPP_MSG":
            msg = cbt.data
            msg_type = msg.get("type", None)
            interface_name = msg["interface_name"]
            # handle connection request
            if msg_type == "con_req":
                msg["data"] = json.loads(msg["data"])
                msg["ip6"]  = self.tincanparams["vnets"][self.ipop_interface_details[interface_name]["index"]]["ip6"]
                log = "recv con_req ({0}): {1}".format(msg["data"]["con_type"], msg["uid"])
                self.registerCBT('Logger', 'debug', log)
                self.registerCBT('TincanSender', 'DO_GET_CAS', msg)


            # handle connection acknowledgement
            elif msg_type == "con_ack":
                msg["data"] = json.loads(msg["data"])
                log = "recv con_ack ({0}): {1}".format(msg["data"]["con_type"], msg["uid"])
                self.registerCBT('Logger', 'debug', log)
                self.create_connection(msg["uid"], msg["data"],interface_name)

                
            # handle ping message
            elif msg_type == "ping":
                # add source node to the list of discovered nodes
                self.ipop_interface_details[interface_name]["discovered_nodes"].append(msg["uid"])
                self.ipop_interface_details[interface_name]["discovered_nodes"] = list(set(self.ipop_interface_details[interface_name]["discovered_nodes"]))
                index = self.ipop_interface_details[interface_name]["index"]
                # reply with a ping response message
                self.send_msg_srv("ping_resp", msg["uid"], self.tincanparams["vnets"][index]["uid"],interface_name)
                log = "recv ping: {0}".format(msg["uid"])
                self.registerCBT('Logger', 'debug', log)

            # handle ping response
            elif msg_type == "ping_resp":
                # add source node to the list of discovered nodes
                self.ipop_interface_details[interface_name]["discovered_nodes"].append(msg["uid"])
                self.ipop_interface_details[interface_name]["discovered_nodes"] = list(
                    set(self.ipop_interface_details[interface_name]["discovered_nodes"]))
                log = "recv ping_resp: {0}".format(msg["uid"])
                self.registerCBT('Logger', 'debug', log)
                
            # handle peer_con_resp sent by peer   
            elif msg_type == "peer_con_resp":
                log = "recv con_resp: {0}".format(msg["uid"])
                self.registerCBT('Logger', 'debug', log)
                
            # Handle xmpp advertisements   
            elif msg_type == "xmpp_advertisement":
                interface_details = self.ipop_interface_details[interface_name]
                interface_details["discovered_nodes_srv"].append(msg["data"])
                interface_details["discovered_nodes_srv"] = list(set(interface_details["discovered_nodes_srv"]))
                log = "recv xmpp_advt: {0}".format(msg["uid"])
                self.registerCBT('Logger', 'debug', log)
                
        # handle and forward tincan data packets
        elif cbt.action == "TINCAN_PACKET":

            reqdata = cbt.data
            interface_name = reqdata["interface_name"]
            data = reqdata["dataframe"]
            # ignore packets when not connected to the overlay
            if self.ipop_interface_details[interface_name]["p2p_state"] != "connected":
                return

            # extract the source uid and destination uid
            # XXX src_uid and dst_uid should be obtained from the header, but
            # sometimes the dst_uid is the null uid
            # FIXME sometimes an irrelevant ip4 address obtained
            src_ip4 = '.'.join(str(int(i, 16)) for i in [data[52:60][i:i+2] for i in range(0, 8, 2)])
            dst_ip4 = '.'.join(str(int(i, 16)) for i in [data[60:68][i:i+2] for i in range(0, 8, 2)])
            index = self.ipop_interface_details[interface_name]["index"]
            ip4_uid_table = self.tincanparams["vnets"][index]["ip4_uid_table"]
            if src_ip4 in ip4_uid_table.keys() and dst_ip4 in ip4_uid_table.keys():
                src_uid = ip4_uid_table[src_ip4]
                dst_uid = ip4_uid_table[dst_ip4]
            else:
                log = "recv illegal tincan_packet: src={0} dst={1}".format(src_ip4, dst_ip4)
                self.registerCBT('Logger', 'error', log)

            destmac,srcmac = data[0:12],data[12:24]
            mac_uid_table  = self.ipop_interface_details[interface_name]["mac_uid_table"]

            if destmac not in mac_uid_table.keys() and srcmac not in mac_uid_table.keys():
                log = "recv illegal tincan_packet: src={0} dst={1}".format(srcmac, destmac)
                self.registerCBT('Logger', 'error', log)
                return
            else:
                dst_uid = mac_uid_table[destmac]
                src_uid = mac_uid_table[srcmac]

            # send forwarded message
            new_msg = {
                "msg_type": "forward",
                "src_uid": src_uid,
                "dst_uid": dst_uid,
                "packet": data
            }

            self.forward_msg("exact", dst_uid, new_msg,interface_name)

            log = "sent tincan_packet (exact): {0}".format(dst_uid)
            self.registerCBT('Logger', 'info', log)

            # add on-demand link
            self.add_on_demand(dst_uid,interface_name)

        # inter-controller communication (ICC) messages
        elif cbt.action == "ICC_CONTROL":
            msg = cbt.data
            msg_type = msg.get("msg_type", None)
            interface_name = msg["interface_name"]
            # advertisement of nearby nodes
            if msg_type == "advertise":
                self.ipop_interface_details[interface_name]["discovered_nodes"]\
                    = list(set(self.ipop_interface_details[interface_name]["discovered_nodes"] + msg["peer_list"]))

                log = "recv advertisement: {0}".format(msg["src_uid"])
                self.registerCBT('Logger', 'info', log)

            # handle forward packet
            elif msg_type == "forward":
                log = "Going to forward the message"+str(msg)
                self.registerCBT('Logger', 'info', log)
                if self.forward_msg("exact", msg["dst_uid"], msg,interface_name):
                    msg["interface_name"] = interface_name
                    #self.registerCBT('TincanSender', 'DO_INSERT_DATA_PACKET', msg)

                    log = "Message at the destination {0}".format(msg["src_uid"])
                    self.registerCBT('Logger', 'info', log)

            # handle find chord
            elif msg_type == "find_chord":

                if self.forward_msg("closest", msg["dst_uid"], msg,interface_name):

                    # forward found_chord message
                    new_msg = {
                        "msg_type": "found_chord",
                        "src_uid": self.tincanparams["vnets"][self.ipop_interface_details[interface_name]]["uid"],
                        "dst_uid": msg["src_uid"],
                        "log_uid": msg["log_uid"]
                    }

                    self.forward_msg("exact", msg["src_uid"], new_msg,interface_name)

            # handle found chord
            elif msg_type == "found_chord":

                if self.forward_msg("closest", msg["dst_uid"], msg,interface_name):

                    self.add_chord(msg["src_uid"], msg["log_uid"],interface_name)

        ##### Changes done as part of IP Multicast
        elif cbt.action == "SEND_PEER_LIST":
            self.registerCBT('Logger', 'info', 'Control inside BaseTopology Manager peerlist code')
            online_peers = []
            interface_name = cbt.data["interface_name"]
            interface_details = self.ipop_interface_details[interface_name]
            for peer in interface_details["peers"].keys():
                if "status" in interface_details["peers"][peer].keys():
                    if interface_details["peers"][peer]["status"] == "online" and peer not in online_peers:
                        online_peers.append(peer)
                if "con_status" in interface_details["peers"][peer].keys():
                    if interface_details["peers"][peer]["con_status"] == "online" and peer not in online_peers:
                        online_peers.append(peer)
            cbtdt = {'peerlist': online_peers,
                     'uid': interface_details["ipop_state"]["_uid"]
                     }
            self.registerCBT('BroadCastForwarder', 'peer_list', cbtdt)
            self.registerCBT('Multicast', 'network_data', cbtdt)

        elif cbt.action == "Send_Receive_Details":
            dataval = cbt.data
            self.sendcount = dataval["send"]
            self.receivecount = dataval["receive"]
            self.registerCBT('Logger', 'info', str(dataval))

        elif cbt.action == "SEND_MAC_Details":
            interface_name = cbt.data["interface_name"]
            self.ipop_interface_details[interface_name]["uid_mac_table"].update(cbt.data["uid_mac_table"])
            self.ipop_interface_details[interface_name]["mac_uid_table"].update(cbt.data["mac_uid_table"])
        ### Changes end here
        else:
            log = '{0}: unrecognized CBT {1} received from {2}'\
                    .format(cbt.recipient, cbt.action, cbt.initiator)
            self.registerCBT('Logger', 'warning', log)

    ############################################################################
    # manage topology                                                          #
    ############################################################################

    def manage_topology(self,interface_name):
        log = "Inside Manager Topology"
        self.registerCBT('Logger', 'info', log)
        # obtain local state
        interface_details = self.ipop_interface_details[interface_name]
        if interface_details["p2p_state"] == "started":
            if not interface_details["ipop_state"]:
                self.registerCBT('Logger', 'info', interface_name+" p2p state: started")
                return
            else:
                interface_details["p2p_state"] = "searching"
                log = "identified local state: {0}".format(interface_details["ipop_state"]["_uid"])
                self.registerCBT('Logger', 'info', log)

        # discover nodes (from XMPP)
        if interface_details["p2p_state"] == "searching":
            if not interface_details["discovered_nodes_srv"] and not interface_details["discovered_nodes"]:
                self.registerCBT('Logger', 'info', interface_name+" p2p state: searching")
                return
            else:
                interface_details["p2p_state"] = "connecting"
                interface_details["discovered_nodes"] = list(set(interface_details["discovered_nodes_srv"]))

        # connecting to the peer-to-peer network
        if interface_details["p2p_state"] == "connecting":

            # if there are no discovered nodes, ping nodes
            if not interface_details["peers"] and not interface_details["discovered_nodes"]:
                self.ping(interface_name)
                return

            log = "discovered nodes: {0}".format(interface_details["discovered_nodes"])
            self.registerCBT('Logger', 'info', log)

            # trim offline connections
            self.clean_connections(interface_name)

            # attempt to bootstrap
            try:
                self.add_successors(interface_name)
            except:
                self.registerCBT('Logger', 'info', "Exception in add_successors")

            # wait until connected
            for peer in interface_details['peers'].keys():
                if self.linked(peer,interface_name):
                    interface_details["p2p_state"] = "connected"
                    break

        # connecting or connected to the IPOP peer-to-peer network; manage local topology
        if interface_details["p2p_state"] == "connected":

            # trim offline connections
            self.clean_connections(interface_name)

            # manage successors
            self.add_successors(interface_name)
            self.remove_successors(interface_name)

            # manage chords
            self.find_chords(interface_name)

            # create advertisements
            self.advertise(interface_name)

            if not interface_details["peers"]:
                interface_details["p2p_state"] = "connecting"
                self.registerCBT('Logger', 'info', interface_name+" p2p state: DISCONNECTED")
            else:
                self.registerCBT('Logger', 'info', interface_name+" p2p state: CONNECTED")

    def timer_method(self):
    
        try:
            self.interval_counter += 1

            # every <interval_management> seconds
            if self.interval_counter % self.CMConfig["interval_management"] == 0:
                for interface_name in self.ipop_interface_details.keys():
                    # manage topology
                    try:
                        self.manage_topology(interface_name)
                    except Exception as error:
                        self.registerCBT('Logger', 'error', "Exception in MT BTM timer: "+str(error))

                    # update local state and update the list of discovered nodes (from XMPP)
                    msg = {"interface_name": interface_name, "uid":""}
                    self.registerCBT('TincanSender', 'DO_GET_STATE', msg)
                    for uid in self.ipop_interface_details[interface_name]["peer_uids"].keys():
                        msg["uid"] = uid
                        self.registerCBT('TincanSender', 'DO_GET_STATE', msg)

                #self.registerCBT('TincanSender', 'DO_ECHO', '')

            # every <interval_ping> seconds
            if self.interval_counter % self.CMConfig["interval_ping"] == 0:

                # ping to repair potential network partitions
                try:
                    self.ping()
                except Exception as error_msg:
                    self.registerCBT('Logger', 'error', "Exception in PING BTM timer:"+ str(error_msg))

            # every <interval_central_visualizer> seconds
            if self.use_visualizer and self.interval_counter % self.cv_interval == 0:
                # send information to central visualizer
                self.visual_debugger()
        except Exception as err:
            self.registerCBT('Logger', 'error', "Exception in BTM timer:"+ str(err))

    def ping(self,interface_name=""):

        # send up to <num_pings> ping messages to random nodes to test if the
        # node is available
        if interface_name == "":
            for i_name in self.ipop_interface_details.keys():
                rand_list = random.sample(
                    range(0, len(self.ipop_interface_details[i_name]["discovered_nodes_srv"])),
                    min(len(self.ipop_interface_details[i_name]["discovered_nodes_srv"]),
                        self.CMConfig["num_pings"]))

                for i in rand_list:
                    index = self.ipop_interface_details[i_name]["index"]
                    self.send_msg_srv("ping", self.ipop_interface_details[i_name]["discovered_nodes_srv"][i],
                                      self.tincanparams["vnets"][index]["uid"],interface_name=i_name)

                # reset list of discovered nodes (from XMPP)
                self.ipop_interface_details[i_name]["discovered_nodes_srv"] = []
        else:
            rand_list = random.sample(range(0, len(self.ipop_interface_details[interface_name]["discovered_nodes_srv"])),
                    min(len(self.ipop_interface_details[interface_name]["discovered_nodes_srv"]), self.CMConfig["num_pings"]))

            for i in rand_list:
                index = self.ipop_interface_details[interface_name]["index"]
                self.send_msg_srv("ping", self.ipop_interface_details[interface_name]["discovered_nodes_srv"][i],
                                  self.tincanparams["vnets"][index]["uid"],interface_name)

            # reset list of discovered nodes (from XMPP)
            self.ipop_interface_details[interface_name]["discovered_nodes_srv"]=[]

    def terminate(self):
        pass

    # visual debugger
    #   send information to the central visualizer
    def visual_debugger(self):
        for interface_name in self.ipop_interface_details.keys():
            # list only connected links
            index = self.ipop_interface_details[interface_name]["index"]
            new_msg = {
                "interface_name": interface_name,
                "type": "BaseTopologyManager",
                "uid": self.tincanparams["vnets"][index]["uid"],
                "ip4": self.tincanparams["vnets"][index]["ip4"],
                "mac": self.ipop_interface_details[interface_name]["mac"],
                "state": self.ipop_interface_details[interface_name]["p2p_state"],
		        "macuidmapping" :self.ipop_interface_details[interface_name]["uid_mac_table"],
		        "sendcount": self.sendcount,
            	"receivecount" : self.receivecount,
                "links": {
                    "successor": [], "chord": [], "on_demand": []
                }
            }

            for con_type in ["successor", "chord", "on_demand"]:
                for peer in self.ipop_interface_details[interface_name]["links"][con_type].keys():
                    if self.linked(peer,interface_name):
                        new_msg["links"][con_type].append(peer)
                self.registerCBT("Visualizer", "SEND_INFO", new_msg)
