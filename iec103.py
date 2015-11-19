# -*- coding:utf-8 -*-
__author__ = 'wuyan'

import socket
import struct
import threading, time
import string


######### ASDU: 类型标识 ######################################################
TYP_ASDU10  = 0x0A
VSQ_81      = 0x81
COT_GW      = 40        # 通用分类写命令（控制方向）
COT_GW_ACK  = 44        # 通用分类写命令确认
COT_GW_EXCUTE_YES  = 40    # 通用分类写命令的肯定认可
COT_GW_EXCUTE_NO   = 41    # 通用分类写命令的否定认可

######### ASDU: 信息体标识符 ######################################################
FUN_GENERAL = 254       # 通用分类功能,ASDU10和ASDU21都适用
INF_GW_WITH_ACK = 249   # 带确认的写条目
INF_GW_WITH_EXCUTE = 250    # 带执行的写条目 240～255为通用分类功能

######### ASDU: 信息元素 ######################################################
KOD_VALUE = 1       # 实际值
GRC_OK = 0          # 通用分类回答码: 认可
GDD_TYPE_NULL = 0   # 无数据
GDD_TYPE_OS8ASCII = 1
GDD_TYPE_BS1   = 2  #成组8位串
GDD_TYPE_UINT = 3
GDD_TYPE_INT = 4
GDD_TYPE_UFLOAT = 5
GDD_TYPE_FLOAT = 6
GDD_TYPE_754S = 7
GDD_TYPE_754 = 8
GDD_TYPE_DPT = 9    # 双点信息
GDD_TYPE_SPT = 10
# 其它GDD类型未列出.


# todo， 暂不处理粘包，如果实际使用中发现有粘包问题，再进行处理: 开辟缓冲存储接收报文
# 一个物理连接使用一个IEC103对象来处理
class IEC103(object):
    SETTING_TYPE_INT = 0
    SETTING_TYPE_IP = 1
    SETTING_TYPE_FLOAT = 2

    def __init__(self, device_ip):
        self.remote_ip = ("198.120.0.19", 6000)
        self.remote_addr = self.get_remote_addr()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock_udp_receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_udp_receive.bind(("", 6002))
        self.sock_udp_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.data_number = 0
        self.data_number_lock = threading.Lock()                    # 避免计算APCI的数据编号时冲突
        self.rii = 0

        self.timer = threading.Timer(10, self.keep_alive_with_no_asdu )     # 心跳定时器(python内部为线程实现)
        self.thread_udp_r = threading.Thread(target=self.udp_receive)
        self.thread_udp_r.start()
        #self.rbuf = []

    def udp_receive(self):
        while True:
            print "udp receive loop"
            data, addr = self.sock_udp_receive.recvfrom(268)    # APCI 28字节，ASDU最大240字节
            print "Received:", repr(data), "from ", addr

    def isconnected(self):
        sock_err = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if sock_err==0:
            print u"处于连接状态"
            return True
        else:
            return False

    def make_data_number(self):
        self.data_number_lock.acquire()
        self.data_number = (self.data_number+1) % 0xFFFF
        self.data_number_lock.release()
        return self.data_number

    def make_rii_number(self):
        self.rii = (self.rii+1) % 0xFF
        return self.rii

    def keep_alive_with_no_asdu(self):
        #发送心跳包
        try:
            apdu = self.pack_asdu_to_apdu("")
            print "send keep alive:", repr(apdu)
            self.sock.sendall(apdu)
        except socket.error as err:
            print err

    def get_remote_addr(self):
        addr = string.atoi(str.rsplit(self.remote_ip[0], '.')[-1], 10) & 0xFF
        #print ord(addr[0]), ord(addr[1])
        return addr

    def connect(self, device_ip):
        self.remote_ip = device_ip
        self.remote_addr = self.get_remote_addr()

        try:
            self.sock.connect(self.remote_ip)
            self.timer.start()  # 开始心跳线程

            return True
        except socket.error as err:
            print err
            return False

    def close(self):
        # 关闭心跳线程
        self.timer.cancel()
        # todo, 关闭udp接收线程
        self.sock.close()

####################################################  规约处理  ########################################################
    def pack_asdu_to_apdu(self, asdu):    # asdu为struct pack后的结果，即为字符串
        wFirstFlag = 0xEB90     # WORD
        wLength = 20+len(asdu)     # DWORD,APCI报文的数据长度为源厂站号、源设备地址、目标厂站号、目标设备地址、数据编号、传输路径首级路由装置地址、传输路径末级路由装置地址、设备类型、设备网络状态、一个保留字节和ASDU报文的长度之和
        wSecondFlag = 0xEB90    # WORD
        wSourceFactoryId = 0    # WORD
        wSourceAddr = 0xC0BB    # WORD
        wDestinationFactoryId = 0 # WORD
        wDestinationAddr = self.remote_addr    # WORD, 和ip的最后一段相同
        wDataNumber = self.make_data_number()         # WORD,  数据编号, 和每个服务端的连接单独计数; 范围为：0----0XFFFF；在连接建立时，设置初始值，发送编号为0、接收判断的编号为-1。
                                    # 对于每一个报文均需判断其数据编号的合法性。若超时数据编号得不到刷新，则断开链接重新链接，数据编号重新设置初始值。在单网通讯的情况下，报文的数据编号没有实际意义，所有的接收报文都认定有效。
                                    # 发送方组织APCI时，将当前的数据编号填入APCI,同时将数据编号增1保留，数据编号溢出时自动归零。具体判断逻辑见7.8
        wDeviceType = 1         # WORD, 设备类型,0代表其他类型，见7.2, 抓包工具为0x01
        wDeviceStatic = 0x10     # WORD, 设备网络状态，表明单机运行,且A网正常
        wFirstRouterAddr = 0    # WORD, 传输路径首级路由装置地址,若未经路由则两个地址的值为0
        wLastRouterAddr = 0     # WORD, 传输路径末级路由装置地址,若未经路由则两个地址的值为0
        wReserve1 = 0x6405      # 保留字0xFFFF, 抓包有时为0x6405

        apdu = struct.pack("<HI11H%ds" % len(asdu),    # <表示为小端字节序;
                          wFirstFlag, wLength, wSecondFlag,wSourceFactoryId, wSourceAddr,wDestinationFactoryId, wDestinationAddr,
                          wDataNumber,wDeviceType, wDeviceStatic, wFirstRouterAddr, wLastRouterAddr ,wReserve1, asdu )
        return apdu

        # 打包单个信息体，包括: GIN、KOD、GDD、GID
    def pack_info_body(self, grp_no, item_no, kod, gdd_type, gdd_datasize, gdd_num, gid_data):
        pack_info = struct.pack("<6B%ds" % len(gid_data),
                                grp_no, item_no, kod, gdd_type, gdd_datasize, gdd_num, gid_data)

        return pack_info

    # 带确认或带执行的写,每个打好包的info包括: GIN、KOD、GDD、GID
    def pack_asdu_10_gw( self, with_excute, pre_rii, info_list):
        # 先打包信息体(要写入的数据列表)，然后再打包ASDU
        pack_info_list = struct.pack("<B",
                                     len(info_list))
        for info in info_list:
            pack_info_list = struct.pack("<%ds%ds" % (len(pack_info_list), len(info)),
                                         pack_info_list, info)

        if with_excute:     # 带执行写只需要NGD，不需要后面的内容
            inf = INF_GW_WITH_EXCUTE
            rii = pre_rii
            pack_asdu = struct.pack("<8B",
               TYP_ASDU10, VSQ_81, COT_GW, self.remote_addr, FUN_GENERAL, inf, 0, len(info_list))
            return pack_asdu
        else:
            rii = self.make_rii_number()
            inf = INF_GW_WITH_ACK
            pack_asdu = struct.pack("<7B%ds" % len(pack_info_list),
                           TYP_ASDU10, VSQ_81, COT_GW, self.remote_addr, FUN_GENERAL, inf, 0, pack_info_list)
            return pack_asdu

    # 整数统一用4个字节打包
    # setting(grp_no, item_no, type, new_value)
    def pack_int_setting(self,setting):
        gid_data = struct.pack("<I", setting[3])
        pack_setting = self.pack_info_body(setting[0], setting[1], KOD_VALUE, GDD_TYPE_INT, 4, 1, gid_data)
        return pack_setting

    # ip用4个字节打包,类似小端字节序: 主机号在前，网络号在后
    # setting(grp_no, item_no, type, new_value)
    def pack_ip_setting(self,setting):
        def valid_ip(address):
            try:
                socket.inet_aton(address)
                return True
            except:
                return False
        ip = setting[3]
        assert (valid_ip(ip))
        ip_segs = [string.atoi(seg) for seg in reversed(string.split(ip, "."))]
        gid_data = struct.pack("<4B", ip_segs[0], ip_segs[1], ip_segs[2], ip_segs[3])
        pack_setting = self.pack_info_body(setting[0], setting[1], KOD_VALUE, GDD_TYPE_UINT, 4, 1, gid_data)
        return pack_setting

    def expect_valid_asdu(self, expect_typ, expect_cot, expect_addr, expect_rii, expect_inf ):
        apci_first_flag, asdu_len, apci_snd_flag = 0,0,0
        typ, vsq, cot, addr, fun, inf, rii, ngd  = 0,0,0,0,0,0,0,0
        while True:
            rbuf = self.sock.recv(28)   # 有效APDU至少28字节
            apci_first_flag, asdu_len, apci_snd_flag = struct.unpack("<HIH", rbuf[0:8])
            print "Received %d bytes with %d bytes asdu: " % (len(rbuf) ,asdu_len-20), repr(rbuf)
            # 判断是否为有效的APCI报文，且包括ASDU内容(过滤掉心跳报文)。如不是，则直接丢弃，进入下一个循环继续接收
            if ((apci_first_flag == 0xEB90) and (apci_snd_flag == 0xEB90) and (asdu_len > 20)):
                rbuf = self.sock.recv(asdu_len-20)
                print "    Received asdu: ", repr(rbuf)
                typ, vsq, cot, addr, fun, inf, rii, ngd = struct.unpack("<8B", rbuf[0:8])
                # 判断是否为需要的ASDU报文，如不是，则丢弃
                if (typ==expect_typ) and (cot==expect_cot) and (addr==expect_addr) and (rii==expect_rii):
                    if (inf == expect_inf):
                        print "        That's what i wanted!"
                        return True
                    else:
                        print "        inf is %x, not my expeced 0x%x" % (inf, expect_inf)
                        return False
                else:
                    print "    expectd asdu:  type is 0x%x, cot is 0x%x, addr is 0x%x, rii is 0x%x" % (typ, cot, addr, rii)
                    print"     received asdu: type is 0x%x, cot is 0x%x, addr is 0x%x, rii is 0x%x" % (expect_typ, expect_cot, expect_addr, expect_rii)
                    pass
            else:
                #print "drop the received data, first_flag is 0x%x, snd_flg is 0x%x, asdu len is %d" % (apci_first_flag, apci_snd_flag, asdu_len)
                pass

    # 整定定值。 其中new_settings为新定值数值的列表，每个定值内容为（组号、点号、数值类型(0表示整数,1表示ip地址)、数值）
    def change_settings(self, new_settings):
        try:
            # 带确认写
            setting_lists = []
            for setting in new_settings:
                if setting[2] == self.SETTING_TYPE_INT:
                    setting_lists.append(self.pack_int_setting(setting))
                elif setting[2] == self.SETTING_TYPE_IP:
                    setting_lists.append(self.pack_ip_setting(setting))
                else:
                    print "Sorry, i can't finish it!"
                    pass
            pack_asdu = self.pack_asdu_10_gw(False, 0, setting_lists)
            pack_apdu = self.pack_asdu_to_apdu(pack_asdu)
            self.sock.sendall(pack_apdu)
            print "Write with Ack. Send %d bytes: " % len(pack_apdu), repr(pack_apdu)
            send_rii = struct.unpack("<B", pack_asdu[6])[0]

            # 接收确认结果
            ack = self.expect_valid_asdu(TYP_ASDU10, COT_GW_ACK, self.remote_addr, send_rii, INF_GW_WITH_ACK)
            if not(ack):
                return False

            # 带执行写
            pack_asdu = self.pack_asdu_10_gw(True, send_rii, setting_lists)
            pack_apdu = self.pack_asdu_to_apdu(pack_asdu)
            self.sock.sendall(pack_apdu)
            print "Write with Excute. Send %d bytes: " % len(pack_apdu), repr(pack_apdu)

            # 接收执行结果
            ack = self.expect_valid_asdu(TYP_ASDU10, COT_GW_EXCUTE_YES, self.remote_addr, send_rii, INF_GW_WITH_EXCUTE)
            if not(ack):
                return False
            else:
                return True

        except socket.error as err:
            print "something iw wront with change_settings!", err

####################################################  规约处理结束  ########################################################

if __name__ == "__main__":
    print "i am fine!"

    iec103 = IEC103(("127.0.0.1, 6001"))
    iec103.connect(("198.120.0.20", 6000))
    iec103.change_settings([ (3, 7, IEC103.SETTING_TYPE_INT, 0)])    #CT额定二次定值。数值0表示1A，数值1表示5A。
    #iec103.change_settings([ (4, 10, IEC103.SETTING_TYPE_IP, "198.120.0.20")])    #CT额定二次定值。数值0表示1A，数值1表示5A。
    iec103.close()

    print "goodbye!"
