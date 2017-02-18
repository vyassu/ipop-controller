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
            self.ipop_interface_details[interface_name]["uid"] = self.tincanparams["vnets"][k]["uid"]
            self.ipop_interface_details[interface_name]["uid_mac_table"]  = {}
            self.ipop_interface_details[interface_name]["mac_uid_table"]  = {}
            self.ipop_interface_details[interface_name]["msgcount"]       = {}
            self.ipop_interface_details[interface_name]["mac"]            = ""
        self.tincanparams = None

    def initialize(self):
        self.registerCBT('Logger', 'info', "{0} Loaded".format(self.ModuleName))

    def processCBT(self, cbt):
        frame = cbt.data.get("dataframe")
        interface_name = cbt.data["interface_name"]
        interface_details = self.ipop_interface_details[interface_name]
        srcmac,destmac,srcip,destip = "","","",""
        if cbt.action == "getlocalmacaddress":
            self.ipop_interface_details[interface_name]["mac"] = cbt.data.get("localmac")
            return
        elif cbt.action == "ARPReply":
            self.registerCBT('Logger', 'debug', "Inside ARP Reply")
            uidmappinglist = cbt.data["msg"]["uidmappinglist"]
            src_uid = cbt.data["msg"]["src_uid"]
            interface_details["uid_mac_table"].update({src_uid:uidmappinglist})
            mac_2_uid_dict = {}
            for mac in uidmappinglist:
                self.ipop_interface_details[interface_name]["mac_uid_table"][mac] = src_uid
                mac_2_uid_dict[mac] = src_uid

            data = {
                "uid_mac_table": {src_uid: uidmappinglist},
                "mac_uid_table": mac_2_uid_dict,
                "interface_name": interface_name,
                "src_node_mac": cbt.data.get("src_node_mac"),
                "location": "remote",
                "type": "update_MAC_UID_tables"
            }
            self.registerCBT('BaseTopologyManager', 'TINCAN_CONTROL', data)

            return
        elif cbt.action=="ARP_PACKET":
            self.registerCBT('Logger', 'info', "Inside Multicast module")
            self.registerCBT('Logger', 'debug', str(cbt.data))
            maclen = int(frame[36:38],16)
            iplen = int(frame[38:40],16)
            op = int(frame[40:44],16)
            srcmacindex = 44 + 2 * maclen
            srcmac = frame[44:srcmacindex]
            srcipindex = srcmacindex + 2 * iplen
            srcip =  '.'.join(str(int(i, 16)) for i in [frame[srcmacindex:srcipindex][i:i+2] for i in range(0, 8, 2)])
            destmacindex = srcipindex + 2 * maclen
            destmac = frame[srcipindex:destmacindex]
            destipindex = destmacindex + 2 * iplen
            destip = '.'.join(str(int(i, 16)) for i in [frame[destmacindex:destipindex][i:i+2] for i in range(0, 8, 2)])
        elif cbt.action == "IP_PACKET":
            destmac, srcmac = frame[0:12], frame[12:24]
            srcip = '.'.join(str(int(i, 16)) for i in [frame[52:60][i:i + 2] for i in range(0, 8, 2)])
            dstip = '.'.join(str(int(i, 16)) for i in [frame[60:68][i:i + 2] for i in range(0, 8, 2)])
            mac_uid_table = self.ipop_interface_details[interface_name]["mac_uid_table"]

        # TO DO Remove the below statements after development
        self.registerCBT('Logger', 'debug', "Source MAC:: "+ str(srcmac))
        self.registerCBT('Logger', 'debug', "Source ip::  " + str(srcip))
        self.registerCBT('Logger', 'debug', "Destination MAC:: " + str(destmac))
        self.registerCBT('Logger', 'debug', "Destination ip:: " + str(destip))

        peer_uids = interface_details["uid_mac_table"].keys()
        current_node_uid = interface_details["uid"]

        if cbt.data["type"] == "local":
            if current_node_uid not in peer_uids:
                interface_details["uid_mac_table"][current_node_uid] =[]
            if int(srcmac,16) != 0:
                interface_details["uid_mac_table"][current_node_uid].append(srcmac)
                self.ipop_interface_details[interface_name]["mac_uid_table"][srcmac] = current_node_uid

            if int(destmac,16) !=0:
                interface_details["uid_mac_table"][current_node_uid].append(destmac)
                interface_details["mac_uid_table"][destmac]  = current_node_uid
            interface_details["uid_mac_table"][current_node_uid]=\
                        list(set(interface_details["uid_mac_table"][current_node_uid]))
            data = {
                        "uid_mac_table": {current_node_uid: [destmac, srcmac]},
                        "mac_uid_table": {destmac: current_node_uid,
                                          srcmac : current_node_uid},
                        "interface_name": interface_name,
                        "location"      : "local",
                        "type": "update_MAC_UID_tables"
            }
        else:
            uid = cbt.data["init_uid"]
            data = {
                    "uid_mac_table": {uid: [destmac, srcmac]},
                    "mac_uid_table": {destmac: uid,srcmac: uid},
                    "interface_name": interface_name,
                    "src_node_mac" : cbt.data.get("init_mac"),
                    "location"     : "remote",
                    "type": "update_MAC_UID_tables"
            }
            if uid not in peer_uids:
                if int(srcmac,16) !=0:
                    interface_details["uid_mac_table"][uid]     = [srcmac]
                    interface_details["mac_uid_table"][srcmac]  = uid
                if int(destmac,16) !=0:
                    interface_details["uid_mac_table"][uid]     +=[destmac]
                    interface_details["mac_uid_table"][destmac] = uid
            else:
                if int(srcmac, 16) != 0:
                    interface_details["uid_mac_table"][uid]     += [srcmac]
                if int(destmac, 16) != 0:
                    interface_details["uid_mac_table"][uid]     += [destmac]

            interface_details["uid_mac_table"][uid]         = list(set(interface_details["uid_mac_table"][uid]))
            interface_details["mac_uid_table"][srcmac]      = uid
            interface_details["mac_uid_table"][destmac]     = uid

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
                if current_node_uid in interface_details["uid_mac_table"].keys():
                    replydata = {
                            "interface_name": interface_name,
                            "src_uid": current_node_uid,
                            "dst_uid": uid,
                            "msg_type": "forward",
                            "msg": {
                                "src_uid": current_node_uid,
                                "src_node_mac": self.ipop_interface_details[interface_name]["mac"],
                                "uidmappinglist": list(self.ipop_interface_details[interface_name]["uid_mac_table"]\
                                                           [current_node_uid]),
                                "message_type": "arpreply"
                            }
                    }
                    self.registerCBT('Logger', 'info', "ARP Reply Data::: "+str(replydata))
                    self.registerCBT('BaseTopologyManager', 'ICC_CONTROL', replydata)
        self.registerCBT('BroadCastForwarder', 'multicast', cbt.data)


        self.registerCBT('Logger', 'debug', str(interface_details["uid_mac_table"]))
        self.registerCBT('BaseTopologyManager','TINCAN_CONTROL', data)


    def terminate(self):
        pass

    def timer_method(self):
        pass