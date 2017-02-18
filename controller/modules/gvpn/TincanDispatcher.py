import json
import sys
import base64,binascii
from controller.framework.ControllerModule import ControllerModule

py_ver = sys.version_info[0]

class TincanDispatcher(ControllerModule):

    def __init__(self, CFxHandle, paramDict, ModuleName):
        super(TincanDispatcher, self).__init__(CFxHandle, paramDict, ModuleName)

    def initialize(self):
        self.registerCBT('Logger', 'info', "{0} Loaded".format(self.ModuleName))

    def timer_method(self):
        pass

    def terminate(self):
        pass

    def processCBT(self, cbt):
        interface_name = ""
        data = cbt.data
        tincan_resp_msg = json.loads(data.decode("utf-8"))["IPOP"]
        req_operation = tincan_resp_msg["Request"]["Command"]
        if "InterfaceName" in tincan_resp_msg["Request"].keys():
            interface_name = tincan_resp_msg["Request"]["InterfaceName"]
        if "Response" in tincan_resp_msg.keys():
            if tincan_resp_msg["Response"]["Success"] == True:
                if req_operation == "QueryNodeInfo":
                        resp_msg = json.loads(tincan_resp_msg["Response"]["Message"])
                        if resp_msg["Type"] == "local":
                            msg = {
                                    "type":"local_state",
                                    "_uid": resp_msg["UID"],
                                    "_ip4": resp_msg["VIP4"],
                                    "_ip6": resp_msg["VIP6"],
                                    "_fpr": resp_msg["Fingerprint"],
                                    "mac" : resp_msg["MAC"],
                                    "interface_name":interface_name
                                }
                            log = "current state of {0} : {1}".format(resp_msg["UID"], str(msg))
                            self.registerCBT('Logger', 'debug', log)
                            self.registerCBT('BaseTopologyManager', 'TINCAN_CONTROL', msg)
                        else:
                            if resp_msg["Status"]!="unknown":
                                msg = {
											"type": "peer_state",
											"uid": resp_msg["UID"],
											"ip4": resp_msg["VIP4"],
											"ip6": resp_msg["VIP6"],
											"fpr": resp_msg["Fingerprint"],
											"mac": resp_msg["MAC"],
											"status": resp_msg["Status"],
                                            "stats": resp_msg["Stats"],
											"interface_name": interface_name
								}
                            else:
                                msg = {
                                    "type": "peer_state",
                                    "uid": resp_msg["UID"],
                                    "ip4": "",
                                    "ip6": "",
                                    "fpr": "",
                                    "mac": "",
                                    "ttl": "",
									"rate": "",
                                    "stats": [],
                                    "status": resp_msg["Status"],
                                    "interface_name": interface_name
                                }
                            log = "current state of {0} : {1}".format(resp_msg["UID"], str(msg))
                            self.registerCBT('Logger', 'debug', log)
                            self.registerCBT('BaseTopologyManager', 'TINCAN_CONTROL', msg)

                elif req_operation == "CreateLinkListener":

                    log = "recv data from Tincan for operation: {0}".format(tincan_resp_msg["Request"]["Command"])
                    self.registerCBT('Logger', 'info', log)
                    self.registerCBT('Logger', 'debug', "Message: "+str(tincan_resp_msg))
                    msg = {
                        "type"  : "con_ack",
                        "uid"   : tincan_resp_msg["Request"]["PeerInfo"]["UID"],
                        "data"  :  {
                                    "fpr"   : tincan_resp_msg["Request"]["PeerInfo"]["Fingerprint"],
                                    "cas"   : tincan_resp_msg['Response']['Message'],
                                    "con_type" : tincan_resp_msg["Request"]["PeerInfo"]["con_type"]
                        },
                        "interface_name": interface_name
                    }
                    self.registerCBT('BaseTopologyManager', 'TINCAN_CONTROL', msg)
                elif req_operation == "ConnectToPeer":
                    log = "recv data from Tincan for operation: {0}".format(tincan_resp_msg["Request"]["Command"])
                    self.registerCBT('Logger', 'info', log)
                    self.registerCBT('Logger', 'debug', "Message: " + str(tincan_resp_msg))
                    msg = {
                        "type": "con_resp",
                        "uid" : tincan_resp_msg["Request"]["PeerInfo"]["UID"],
                        "data": {
                            "fpr": tincan_resp_msg["Request"]["PeerInfo"]["Fingerprint"],
                            "cas": tincan_resp_msg["Request"]["PeerInfo"]["CAS"],
                            "con_type": tincan_resp_msg["Request"]["PeerInfo"]["con_type"]
                        },
                        "status": "online",
                        "interface_name": interface_name
                    }
                    self.registerCBT('BaseTopologyManager', 'TINCAN_CONTROL', msg)

                else:
                    log = "recv data from Tincan: {0}".format(str(tincan_resp_msg))
                    #self.registerCBT('Logger', 'info', log)

            else:
                request_msg = tincan_resp_msg
                request_msg.pop("Response")
                #request_msg["Request"] = "tincan"+ str(tincan_resp_msg["Request"]).split("_")[0]
                '''
                Do not blindly retry, the request will more than likely continue to fail.
                This also isn't properly formatted - its mssing the header info
                #self.registerCBT('TincanSender', 'DO_RETRY', request_msg)
                '''
        else:
            req_peer_list = {
                "interface_name": interface_name,
                "type": "get_peer_list",
            }
            if req_operation == "ICC":
                log = "recv data from Tincan for operation: {0}".format(tincan_resp_msg["Request"]["Command"])
                self.registerCBT('Logger', 'debug', log)
                iccmsg = json.loads(tincan_resp_msg["Request"]["Data"])

                self.registerCBT('BaseTopologyManager', 'TINCAN_CONTROL', req_peer_list)
                self.registerCBT('Logger', 'info', "iccmsg::"+str(iccmsg))

                if "msg" in iccmsg.keys():
                    iccmsg["msg"]["type"] = "remote"
                    iccmsg["msg"]["interface_name"] = tincan_resp_msg["Request"]["InterfaceName"]
                    if "message_type" in iccmsg["msg"]:
                        if iccmsg["msg"]["message_type"] == "arpreply":
                            self.registerCBT('Multicast', 'ARPReply', iccmsg)
                        elif iccmsg["msg"]["message_type"] == "multicast":
                            dataframe = iccmsg["msg"]["dataframe"]
                            if str(dataframe[24:28]) == "0800":
                                self.registerCBT('Multicast', 'IP_PACKET', iccmsg["msg"])
                            else:
                                self.registerCBT('Multicast', 'ARP_PACKET', iccmsg["msg"])
                        else:
                            self.registerCBT('BaseTopologyManager', 'ICC_CONTROL', iccmsg["msg"])
                    else:
                        self.registerCBT('BroadCastController', 'broadcast', iccmsg["msg"])
                else:
                    iccmsg["interface_name"] = tincan_resp_msg["Request"]["InterfaceName"]
                    self.registerCBT('BaseTopologyManager', 'ICC_CONTROL', iccmsg)

            elif req_operation == "UpdateRoutes":
            ### Changes done as part of Multicast ####
                self.registerCBT('BaseTopologyManager', 'TINCAN_CONTROL',req_peer_list)
                pkd = tincan_resp_msg["Request"]["Data"]
                interface_name = tincan_resp_msg["Request"]["InterfaceName"]
                msg = pkd

                #hexmsg = binascii.b2a_hex(msg)
                datagram = {
                        "dataframe": msg,
                        "interface_name": interface_name,
                        "type": "local"
                }
                log = "recv data from Tincan::{0}".format(datagram)
                self.registerCBT('Logger', 'info', log)
                if str(msg[24:28]) == "0800":
                    #self.registerCBT("BaseTopologyManager", "TINCAN_PACKET", datagram)
                    self.registerCBT('Multicast', 'IP_PACKET', datagram)
                elif str(msg[24:28]) == "0806":
                    print("ARP/RevereseARP Packet obtained from Tincan")
                    datagram["message_type"] = "multicast"
                    self.registerCBT('Multicast', 'ARP_PACKET', datagram)
                else:
                    datagram["message_type"] = "broadcast"
                    self.registerCBT('BroadCastController', 'broadcast', datagram)
