import enum
import json
import requests
import logging

logging.basicConfig(level=logging.DEBUG)


class WebRPCMethods(enum.Enum):
    SET_TABLE = "set_table"
    GET_SWITCH_DETAILS = "get_switch_desc"
    GET_FLOW_ENTRIES = "get_flow_stats"
    GET_SWITCHES = "get_switches"


class PayloadGenerator:
    @staticmethod
    def get_flow_entries(dpid):
        payload={}
        payload["method"]=WebRPCMethods.GET_FLOW_ENTRIES.value
        payload["id"] = 1
        params = {}
        params["dpid"] = dpid
        payload["params"]=params
        return json.dumps(payload)

    @staticmethod
    def block(ip, dpid,controller):
        payload = {}
        payload["method"] = WebRPCMethods.SET_TABLE.value
        payload["id"] = 1
        params = {}
        params["dpid"] = dpid
        blocking_flow = {
            "actions": [
                {"type": "OFPAT_OUTPUT", "port": "OFPP_IN_PORT"}
            ],
            "match": {"nw_src": f"{ip}/32", "dl_type": "0x0800", "nw_proto": 6},
        }
        flows = controller.get_flow_entries()["result"]["flowstats"]
        max_priority=max(a["priority"] for a in flows)
        print(max_priority+1)
        blocking_flow["priority"]=max_priority+1
        flows.append(blocking_flow)
        params["flows"] = flows
        payload["params"] = params
        return json.dumps(payload)
        pass


class Connection:
    def __init__(self, addr, port,dpid = "00-00-00-00-00-01") -> None:
        self.addr = addr
        self.port = port
        self.dpid=dpid
    
    @classmethod
    def get_connection(cls,addr,port):
        if not (addr and port):
            return None
        return cls(addr,port)
        

    def block(self, ip):
        logging.info(f"Sending request to block {ip}")
        # print(PayloadGenerator.block(ip, self.dpid,self))
        r = requests.post(
            f"http://{self.addr}:{self.port}/OF/", data=PayloadGenerator.block(ip, self.dpid,self)
        )
        
        logging.debug(f"BLOCK RESPONSE: {r.text}")
    def get_flow_entries(self):
        r = requests.post(
            f"http://{self.addr}:{self.port}/OF/", data=PayloadGenerator.get_flow_entries(self.dpid)
        )
        logging.debug(f"GET FLOW ENTRIES RESPONSE: {r.text}")
        return r.json()
    pass

