from controller.framework.ControllerModule import ControllerModule
import time

class Multicast(ControllerModule):
    def __init__(self, CFxHandle, paramDict, ModuleName):
        super(Multicast, self).__init__(CFxHandle, paramDict, ModuleName)
        self.ConfigData = paramDict
        self.tincanparams = self.CFxHandle.queryParam("Tincan")
        self.ipop_interface_details = {}
        for k in range(len(self.tincanparams["vnets"])):
            interface_name  = self.tincanparams["vnets"][k]["ipoptap_name"]

            self.ipop_interface_details[interface_name] = {}
            interface_detail                            = self.ipop_interface_details[interface_name]
            interface_detail["uid"]                     = self.tincanparams["vnets"][k]["uid"]
            interface_detail["msgcount"]                = {}
            interface_detail["mac"]                     = ""
            interface_detail["local_peer_mac_address"]  = []
        self.tincanparams = None

    def initialize(self):
        self.registerCBT('Logger', 'info', "{0} Loaded".format(self.ModuleName))

    def processCBT(self, cbt):
        frame               = cbt.data.get("dataframe")
        interface_name      = cbt.data["interface_name"]
        interface_details   = self.ipop_interface_details[interface_name]
        srcmac,destmac,srcip,destip = "","","",""

        if cbt.action == "getlocalmacaddress":
            self.ipop_interface_details[interface_name]["mac"] = cbt.data.get("localmac")
            return
        elif cbt.action == "RECV_PEER_MAC_DETAILS":
            self.registerCBT('Logger', 'info', "Inside Multicast Module Update Peer MAC details")
            self.registerCBT('Logger', 'info', "Multicast Message:: "+str(cbt.data))
            uidmappinglist  = cbt.data["msg"]["uidmappinglist"]
            src_uid         = cbt.data["msg"]["src_uid"]
            mac_2_uid_dict  = {}

            for mac in uidmappinglist:
                mac_2_uid_dict[mac] = src_uid

            UpdateBTMMacUIDTable = {
                "uid_mac_table"     : {
                    src_uid: uidmappinglist
                },
                "mac_uid_table"     : mac_2_uid_dict,
                "interface_name"    : interface_name,
                "location"          : "remote",
                "type"              : "UpdateMACUID"
            }
            self.registerCBT('BaseTopologyManager', 'TINCAN_CONTROL', UpdateBTMMacUIDTable)
            return
        elif cbt.action=="ARP_PACKET":
            self.registerCBT('Logger', 'info', "Inside Multicast ARP module")
            self.registerCBT('Logger', 'debug', "Multicast Message::"+str(cbt.data))
            maclen      = int(frame[36:38],16)
            iplen       = int(frame[38:40],16)
            op          = int(frame[40:44],16)
            srcmacindex = 44 + 2 * maclen
            srcmac      = frame[44:srcmacindex]
            srcipindex  = srcmacindex + 2 * iplen
            srcip       =  '.'.join(str(int(i, 16)) for i in [frame[srcmacindex:srcipindex][i:i+2] for i in range(0, 8, 2)])
            destmacindex= srcipindex + 2 * maclen
            destmac     = frame[srcipindex:destmacindex]
            destipindex = destmacindex + 2 * iplen
            destip      = '.'.join(str(int(i, 16)) for i in [frame[destmacindex:destipindex][i:i+2] for i in range(0, 8, 2)])
        elif cbt.action == "IP_PACKET":
            self.registerCBT('Logger', 'info', "Inside Multicast IP module")
            self.registerCBT('Logger', 'debug', "Multicast Message::" + str(cbt.data))
            destmac, srcmac = frame[0:12], frame[12:24]
            srcip = '.'.join(str(int(i, 16)) for i in [frame[52:60][i:i + 2] for i in range(0, 8, 2)])
            dstip = '.'.join(str(int(i, 16)) for i in [frame[60:68][i:i + 2] for i in range(0, 8, 2)])

        # TO DO Remove the below statements after development
        self.registerCBT('Logger', 'debug', "Source MAC:: "+ str(srcmac))
        self.registerCBT('Logger', 'debug', "Source ip::  " + str(srcip))
        self.registerCBT('Logger', 'debug', "Destination MAC:: " + str(destmac))
        self.registerCBT('Logger', 'debug', "Destination ip:: " + str(destip))

        current_node_uid = interface_details["uid"]

        if cbt.data["type"] == "local":
            mac_2_uid_dict = {}
            if int(srcmac,16) != 0:
                interface_details["local_peer_mac_address"].append(srcmac)
                mac_2_uid_dict[srcmac]   = current_node_uid
            if int(destmac,16) !=0:
                interface_details["local_peer_mac_address"].append(destmac)
                mac_2_uid_dict[destmac]  = current_node_uid
            interface_details["local_peer_mac_address"] = list(set(interface_details["local_peer_mac_address"]))
            UpdateBTMMacUIDTable = {
                "uid_mac_table": {
                    current_node_uid: interface_details["local_peer_mac_address"]
                },
                "mac_uid_table": mac_2_uid_dict,
                "interface_name": interface_name,
                "location": "local",
                "type": "UpdateMACUID"
            }

        else:
            uid = cbt.data["init_uid"]
            mac_2_uid_dict = {}
            uid_2_mac_list = []
            if int(srcmac, 16) != 0:
                uid_2_mac_list.append(srcmac)
                mac_2_uid_dict[srcmac] = uid
            if int(destmac, 16) != 0:
                uid_2_mac_list.append(destmac)
                mac_2_uid_dict[destmac] = uid

            UpdateBTMMacUIDTable = {
                "uid_mac_table"     : {uid :uid_2_mac_list},
                "mac_uid_table"     : mac_2_uid_dict,
                "interface_name"    : interface_name,
                "location"          : "remote",
                "type"              : "UpdateMACUID"
            }

            if uid not in list(interface_details["msgcount"].keys()):
                interface_details["msgcount"][uid] = 1
            else:
                interface_details["msgcount"][uid] += 1

            if interface_details["msgcount"][uid] > self.ConfigData["on_demand_threshold"]:
                msg = {
                         "msg_type" : "add_on_demand",
                         "uid"      : uid,
                        "interface_name" : interface_name
                }
                self.registerCBT("BaseTopologyManager","ICC_CONTROL",msg)

            if cbt.action == "ARP_PACKET":
                sendlocalmacdetails = {
                        "interface_name": interface_name,
                        "src_uid"       : current_node_uid,
                        "dst_uid"       : uid,
                        "msg_type"      : "forward",
                        "msg"           : {
                                "src_uid"       : current_node_uid,
                                "src_node_mac"  : interface_details["mac"],
                                "uidmappinglist": interface_details["local_peer_mac_address"],
                                "message_type"  : "SendMacDetails"
                        }
                }
                self.registerCBT('Logger', 'debug', "Sending Local/Peer MAC details:: "+str(sendlocalmacdetails))
                self.registerCBT('BaseTopologyManager', 'ICC_CONTROL', sendlocalmacdetails)
        self.registerCBT('BroadCastForwarder', 'multicast', cbt.data)
        self.registerCBT('BaseTopologyManager','TINCAN_CONTROL', UpdateBTMMacUIDTable)


    def terminate(self):
        pass

    def timer_method(self):
        pass