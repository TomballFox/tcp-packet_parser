import numpy as np
import os
import pandas as pd

path="PATH TO DIRECTORY"
files = os.listdir(path)

class ethernet_protocol:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)
    def __init__(self, buffer):
        self.destination=buffer[0:6]
        self.source=buffer[6:12]
        self.type=buffer[12:14]
    def __dict__(self):
        return {
            "destinationMAC":self.destination.astype(np.uint8).data.hex(),
            "sourceMAC":self.source.astype(np.uint8).data.hex(),
            "ethType":self.source.astype(np.uint8).data.hex()
        }
        
class ipv4_protocol:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)
    def __init__(self, buffer):
        self.version=buffer[0:1]
        self.service_field=buffer[1:2]
        self.total_length=buffer[2:4]
        self.identification=buffer[4:6]
        self.flags=buffer[6:8]
        self.ttl=buffer[8:9]
        self.protocol=buffer[9:10]
        self.header_checksum=buffer[10:12]
        self.source_addr=buffer[12:16]
        self.destination_addr=buffer[16:20]
    def __dict__(self):
        return {
            "ipv4_version":self.version.astype(np.uint8).data.hex(),
            "service_field":self.service_field.astype(np.uint8).data.hex(),
            "total_length":self.total_length[0]*256+self.total_length[1],
            "identification1b":self.identification[0],
            "identification2b":self.identification[1],
            "flags":self.flags.astype(np.uint8).data.hex(),
            "ttl":self.ttl[0],
            "protocol":self.protocol[0],
            "header_checksum":self.header_checksum.astype(np.uint8).data.hex(),
            "source_IP":str(self.source_addr[0])+"."+str(self.source_addr[1])+"."+str(self.source_addr[2])+"."+str(self.source_addr[3]),
            "destination_IP":str(self.destination_addr[0])+"."+str(self.destination_addr[1])+"."+str(self.destination_addr[2])+"."+str(self.destination_addr[3]),
        }
        
class transmission_protocol:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)
    def __init__(self, buffer):
        self.source_port=buffer[0:2]
        self.destination_port=buffer[2:4]
        self.sequence_number=buffer[4:8]
        self.acknowledgment_number=buffer[8:12]
        self.flags=buffer[12:14]
        self.window=buffer[14:16]
        self.checksum=buffer[16:18]
        self.urgent_pointer=buffer[18:20]
        self.data=no_tls(buffer[20:]) if (self.flags==np.array([80,16])).all() else 0
        self.data=tls_13(buffer[20:]) if (self.flags==np.array([80,24])).all() else no_tls(buffer[20:])
    def __dict__(self):
        result = {
            "source_port":self.source_port[0]*256+self.source_port[1],
            "destination_port":self.destination_port[0]*256+self.destination_port[1],
            "sequence_number":int(str(self.sequence_number[0])+str(self.sequence_number[1])+str(self.sequence_number[2])+str(self.sequence_number[3])),
            "acknowledgment_number":int(str(self.acknowledgment_number[0])+str(self.acknowledgment_number[1])+str(self.acknowledgment_number[2])+str(self.acknowledgment_number[3])),
            "trns_flags":self.flags.astype(np.uint8).data.hex(),
            "window":self.window[0]*256+self.window[1],
            "trns_checksum":self.checksum.astype(np.uint8).data.hex()
        }
        result.update(self.data.__dict__())
        return result
    
class no_tls:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)
    def __init__(self, buffer):
        self.data=buffer
    def decode_data(self):
        return bytearray.fromhex(self.data.astype(np.uint8).data.hex()).decode(encoding='utf-8',
                 errors='ignore')
    def __dict__(self):
        return {
            "data":self.data.astype(np.uint8).data.hex()
        }
    
class tls_13(no_tls):
    def __init__(self, buffer):
        self.type=buffer[0:1]
        self.version=buffer[1:3]
        self.length=buffer[3:5]
        self.data=buffer[5:]
    
        
class tcp_Packet:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)
    def __init__(self, path):
        with open(path, "rb") as f:
            self.eth=ethernet_protocol(np.array(list(f.read(14))))
            self.ip=ipv4_protocol(np.array(list(f.read(20))))
            self.trans=transmission_protocol(np.array(list(f.read())))
    def __dict__(self):
        result=self.eth.__dict__()
        result.update(self.ip.__dict__())
        result.update(self.trans.__dict__())
        return result


packets=[]
for file in files:
    packets.append(tcp_Packet(path+file))
df=pd.DataFrame(columns=["destinationMAC",
                        "sourceMAC",
                        "ethType",
                        "ipv4_version",
                        "service_field",
                        "total_length",
                        "identification1b",
                        "identification2b",
                        "flags",
                        "ttl",
                        "protocol",
                        "header_checksum",
                        "source_IP",
                        "destination_IP",
                        "source_port",
                        "destination_port",
                        "sequence_number",
                        "acknowledgment_number",
                        "trns_flags",
                        "window",
                        "trns_checksum",
                        "data",
                        ])
for packet in packets:
    df=pd.concat([df,pd.DataFrame(packet.__dict__(),index=[0])])
