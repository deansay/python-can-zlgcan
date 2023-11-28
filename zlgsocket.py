import socketserver
import threading
import logging
import time
import zlgcan
import traceback
import re

class Parser:
    def __init__(self):
        self.buffer = ''

    def parse(self, data):
        self.buffer += data
        matches = re.findall('<(.*?)>', self.buffer)
        self.buffer = re.sub('<(.*?)>', '', self.buffer)
        return matches
    
'''
黄色： CAN H
绿色： CAN L
'''
log = logging.getLogger(__name__)
        
class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    parser = Parser()
    def handle(self):
        client_address = self.client_address
        
        print(f"客户端 {client_address} 已连接。")
        
        self.say_hi()
        self.stop_event = threading.Event()
        self.chn_handle = None
        self.internal_fd = False
        try:
            while True:
                data = self.request.recv(2048)
                if not data:
                    print(f"客户端 {client_address} 已断开连接。")
                    break

                self.recv_internal(data.decode("ascii"))
        except Exception as e:
            log.error(f"Failed to receive: {e}")
            if self.chn_handle != None:
                self.zcanlib.CloseDevice(self.chn_handle)
                self.chn_handle = None
                self.stop_event.set()
                
            #self.producer_thread_loop = False
            
    def say(self, response):
        try:
            response_bytes = response.encode()
            self.request.sendall(response_bytes)
            return True
        except Exception as e:
            log.error(f"Failed to receive: {e}")
            return False       
        
    def say_hi(self):
        return self.say('< hi >')
        
    def say_ok(self):
        return self.say('< ok >')
    
    def say_nok(self):
        return self.say('< nok >')
            
    def recv_internal(self, ascii_msg):
        matches = self.parser.parse(ascii_msg)
        
        for mat in enumerate(matches):
            data = f"<{mat[1]}>"
            self.parse_message(data)
               
    def parse_message(self, ascii_msg):
        if ascii_msg.startswith("< open ") and ascii_msg.endswith(" >"):
            part = ascii_msg[7:-2]
            pram = part.split(" ")
            
            channel     = int(pram[0][3:])
            devicetype  = int(pram[1])
            fd          = int(pram[2])
            
            if self.open_channel(channel, devicetype,fd) == True:
                return self.say_ok()
            else:
                return self.say_nok()
  
            
        if ascii_msg == ("< rawmode >"):
            return self.say_ok()
            
        if ascii_msg.startswith("< send ") and ascii_msg.endswith(" >"):
            msg = self.ascii_send_message(ascii_msg)
            log.debug(f"send {ascii_msg}")
            
    def open(self,channel, devicetype,fd) -> None:
        """
        Write the token to open the interface
        """
        self.internal_fd = True if fd == 1 else False
        self.channel = channel
        self.zcanlib = zlgcan.zcan() 
        #self.zglhandle = self.zcanlib.OpenDevice(zlgcan.ZCAN_USBCAN2, 0,0)
        self.zglhandle = self.zcanlib.OpenDevice(devicetype, 0,0)
        
        if self.zglhandle == zlgcan.INVALID_DEVICE_HANDLE:
            #assert self.zglhandle is not None, "Open Device failed!"
            return False
            
        ip = self.zcanlib.GetIProperty(self.zglhandle)
        
        ip = self.zcanlib.GetIProperty(self.zglhandle)
        self.zcanlib.SetValue(ip, '0' + "/initenal_resistance", '1')
        self.zcanlib.ReleaseIProperty(ip)
                
        if self.internal_fd == True: #CAN FD enable
            self.zcanlib.SetValue(ip, str(self.channel) + "/clock", "60000000")
            self.zcanlib.ReleaseIProperty(ip)
            
        chn_init_cfg = zlgcan.ZCAN_CHANNEL_INIT_CONFIG()
        chn_init_cfg.can_type = zlgcan.ZCAN_TYPE_CANFD if fd else zlgcan.ZCAN_TYPE_CAN
        
        if self.internal_fd == True:
            chn_init_cfg.config.canfd.mode = 0
            chn_init_cfg.config.canfd.abit_timing = 104286
            chn_init_cfg.config.canfd.dbit_timing = 4260362
        else:
            chn_init_cfg.config.can.timing0 = 0
            chn_init_cfg.config.can.timing1 = 28
            chn_init_cfg.config.can.mode = 0
            chn_init_cfg.config.can.acc_code = 0
            chn_init_cfg.config.can.acc_mask = 0xFFFFFFFF
        
        self.chn_handle = self.zcanlib.InitCAN(self.zglhandle, self.channel, chn_init_cfg)
        
        if self.chn_handle is None:
            return False
    
        self.zcanlib.StartCAN(self.chn_handle)
        self.producer_thread_loop = True
        self.producer_thread = threading.Thread(target=self.receive, args=(self.chn_handle,self.stop_event,))  
        self.producer_thread.start()
        
        return True
        
    def open_channel(self, channel, devicetype,fd):
        log.debug(channel)
        return self.open(channel, devicetype,fd)
    
    def receive(self, chn_handle, stop_event):
        loop = True
        while not stop_event.is_set() and loop:
            rcv_num = self.zcanlib.GetReceiveNum(chn_handle, zlgcan.ZCAN_TYPE_CAN)
            rcv_canfd_num = self.zcanlib.GetReceiveNum(chn_handle, zlgcan.ZCAN_TYPE_CANFD)
            if rcv_num:
                rcv_msg, rcv_num = self.zcanlib.Receive(chn_handle, rcv_num)
                for i in range(rcv_num):
                    resp = self.message_to_ascii(rcv_msg[i].frame.can_id, False, rcv_msg[i].frame.data, rcv_msg[i].frame.can_dlc,int(time.time()))
                    log.debug(f"recv {resp}")
                    
                    if self.say(resp) == False:
                        log.debug("loop exit!")
                        loop = False
                    
            elif rcv_canfd_num:
                rcv_canfd_msgs, rcv_canfd_num = self.zcanlib.ReceiveFD(chn_handle, rcv_canfd_num)
                for i in range(rcv_canfd_num):
                    resp = self.message_to_ascii(rcv_canfd_msgs[i].frame.can_id, False, rcv_canfd_msgs[i].frame.data, rcv_canfd_msgs[i].frame.len,int(time.time()))
                    log.debug(f"recv {resp}")
                    
                    if self.say(resp) == False:
                        log.debug("loop exit!")
                        loop = False
            else:
                time.sleep(0.05)
                #log.debug('receive running..')
    
    def message_to_ascii(self,can_id, is_extended_id, data, dlc, timestamp):
        # Note: socketcan bus adds extended flag, remote_frame_flag & error_flag to id
        # not sure if that is necessary here
        length = dlc
        if is_extended_id:
            can_id_string = f"{(can_id&0x1FFFFFFF):08X}"
        else:
            can_id_string = f"{(can_id&0x7FF):03X}"
        # Note: seems like we cannot add CANFD_BRS (bitrate_switch) and CANFD_ESI (error_state_indicator) flags
        bytes_string = "".join(f"{x:02x}" for x in data[0:length])
        
        return f"< frame {can_id_string} {timestamp} {bytes_string} >"
        
    def ascii_send_message(self, ascii_msg: str): #-> can.Message:
        frame_string = ascii_msg[7:-2]
        parts   = frame_string.split(" ", 2)
        can_id  = int(parts[0], 16)
        can_dlc = int(parts[1], 16)
    
        payload = parts[2].split(' ')
        
        if self.internal_fd == True:    
            msgs = (zlgcan.ZCAN_TransmitFD_Data * 1)()
        else:
            msgs = (zlgcan.ZCAN_Transmit_Data * 1)()
    
        msgs[0].transmit_type = 0
        msgs[0].frame.eff     = 0
        msgs[0].frame.rtr     = 0
        
        msgs[0].frame.can_id     =  can_id
        
        if not self.internal_fd:
            msgs[0].frame.can_dlc    =  can_dlc
        else:
            msgs[0].frame.brs     = 1 if self.internal_fd == True else 0
            msgs[0].frame.len     = int(parts[1], 16)
            

        for i in range(len(payload)):
            msgs[0].frame.data[i] = int(payload[i],16) 

        if self.internal_fd == True:
            self.zcanlib.TransmitFD(self.chn_handle, msgs, 1)
        else:        
            self.zcanlib.Transmit(self.chn_handle, msgs, 1)            
                
    def ascii_frame_message(self, ascii_msg: str):# -> can.Message:
        if not ascii_msg.startswith("< frame ") or not ascii_msg.endswith(" >"):
            log.warning(f"Could not parse ascii message: {ascii_msg}")
            return None
        else:
            # frame_string = ascii_msg.removeprefix("< frame ").removesuffix(" >")
            frame_string = ascii_msg[8:-2]
            parts = frame_string.split(" ", 3)
            can_id, timestamp = int(parts[0], 16), float(parts[1])
            is_ext = len(parts[0]) != 3

            data = bytearray.fromhex(parts[2])
            can_dlc = len(data)

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    host = '0.0.0.0'
    port = 12346
    server = ThreadedTCPServer((host, port), ThreadedTCPRequestHandler)
    logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')
    print(f"服务器启动，监听端口：{port}")

    server.serve_forever()
