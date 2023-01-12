"""
这是等待你完成的代码。正常情况下，本文件是你唯一需要改动的文件。
你可以任意地改动此文件，改动的范围当然不限于已有的五个函数里。（只要已有函数的签名别改，要是签名改了main里面就调用不到了）
在开始写代码之前，请先仔细阅读此文件和api文件。这个文件里的五个函数是等你去完成的，而api里的函数是供你调用的。
提示：TCP是有状态的协议，因此你大概率，会需要一个什么样的数据结构来记录和维护所有连接的状态
"""
from api import *
import random
import struct
import time
from array import array
from typing import Dict
from enum import Enum, unique
from scapy.all import *
from scapy.layers.inet import IP, TCP

@unique
class State(Enum):
    CLOSED          = 0
    # LITSEN          = 1
    SYN_SENT        = 2
    ESTABISHED      = 3
    FIN_WAIT1       = 4
    FIN_WAIT2       = 5
    CLOSING         = 6
    TIMEWAIT        = 7
    CLOSE_WAIT      = 8
    LAST_ACK        = 9

# 连接状态
class Connection(object):
    def __init__(self, state:str, seq:int, ack:int):
        self.state = state
        self.seq = seq
        self.ack = ack

conns : Dict[str, Connection] = {}

def app_connect(conn: ConnectionIdentifier):
    """
    当有应用想要发起一个新的连接时，会调用此函数。想要连接的对象在conn里提供了。
    你应该向想要连接的对象发送SYN报文，执行三次握手的逻辑。
    当连接建立好后，你需要调用app_connected函数，通知应用层连接已经被建立好了。
    :param conn: 连接对象
    :return: 
    """
    # 创建连接记录
    conns[str(conn)] = Connection(State.CLOSED, 0, 0)

    # 发送SYN报文
    seq = random.randint(1, 1<<32 - 1)
    conns[str(conn)].seq = seq
    tcp_tx(conn, tcp_pkt(conn, flags=2, seq=seq, ack=0))

    # 进入SYN-SENT状态
    conns[str(conn)].state = State.SYN_SENT

    print("app_connect", conn)


def app_send(conn: ConnectionIdentifier, data: bytes):
    """
    当应用层想要在一个已经建立好的连接上发送数据时，会调用此函数。
    :param conn: 连接对象
    :param data: 数据内容，是字节数组
    :return:
    """
    # 发送报文
    seq = conns[str(conn)].seq
    ack = conns[str(conn)].ack
    # pkt = IP(src=conn["src"]["ip"],
    #          dst=conn["dst"]["ip"])/TCP(dport=conn["dst"]["port"],
    #                                     sport=conn["src"]["port"],
    #                                     flags=24, seq=seq, ack=ack)/data
    # pkt = raw(pkt)
    # tcp_tx(conn, pkt)
    tcp_tx(conn, tcp_pkt(conn, flags=24, seq=seq, ack=ack, data=data))

    print("app_send", conn, data.decode(errors='replace'))


def app_fin(conn: ConnectionIdentifier):
    """
    当应用层想要半关闭连接(FIN)时，会调用此函数。
    :param conn: 连接对象
    :return: 
    """
    # 发送FIN报文
    seq = conns[str(conn)].seq
    ack = conns[str(conn)].ack
    tcp_tx(conn, tcp_pkt(conn, flags=17, seq=seq, ack=ack))

    # 进入FIN-WAIT1状态
    conns[str(conn)].state = State.FIN_WAIT1

    print("app_fin", conn)


def app_rst(conn: ConnectionIdentifier):
    """
    当应用层想要重置连接(RES)时，会调用此函数
    :param conn: 连接对象
    :return: 
    """
    # TODO 请实现此函数
    print("app_rst", conn)


def tcp_rx(conn: ConnectionIdentifier, data: bytes):
    """
    当收到TCP报文时，会调用此函数。
    正常情况下，你会对TCP报文，根据报文内容和连接的当前状态加以处理，然后调用0个~多个api文件中的函数
    :param conn: 连接对象
    :param data: TCP报文内容，是字节数组。（含TCP报头，不含IP报头）
    :return: 
    """
    # TODO 请实现此函数
    header = parse_tcp_header(data[:20])
    flags = header['flags']
    # print(header)
    # print(header['src_port'], ' ', header['dst_port'], ' ', flags)

    if conns[str(conn)].state == State.CLOSED:
        pass
    elif conns[str(conn)].state == State.SYN_SENT:
        # 收到SYN-ACK
        if flags == 18:
            # 回复ACK
            conns[str(conn)].seq = header['ack_num']
            conns[str(conn)].ack = header['seq_num'] + 1
            seq = conns[str(conn)].seq
            ack = conns[str(conn)].ack
            tcp_tx(conn, tcp_pkt(conn, flags=16, seq=seq, ack=ack))
            # 通知应用层
            app_connected(conn)
            # 完成三次握手，进入ESTABLISHED阶段
            conns[str(conn)].state = State.ESTABISHED

    elif conns[str(conn)].state == State.ESTABISHED:
        # 收到FIN报文
        if flags == 17:
            # 回复ACK
            conns[str(conn)].seq = header['ack_num']
            conns[str(conn)].ack = header['seq_num'] + 1
            seq = conns[str(conn)].seq
            ack = conns[str(conn)].ack
            tcp_tx(conn, tcp_pkt(conn, flags=16, seq=seq, ack=ack))
            # 进入CLOSE_WAIT阶段
            conns[str(conn)].state = State.CLOSE_WAIT
            # 通知应用层半关闭
            app_peer_fin(conn)
            # 发送FIN报文
            seq = conns[str(conn)].seq
            ack = conns[str(conn)].ack
            tcp_tx(conn, tcp_pkt(conn, flags=17, seq=seq, ack=ack))
            # 进入LAST_ACK阶段
            conns[str(conn)].state = State.LAST_ACK
        # 收到数据
        else:
            # 回复ACK
            print("data_len: {}  header_len: {}".format(len(data), header['header_length']))
            data_len = len(data) - header['header_length'] * 4
            conns[str(conn)].seq = header['ack_num']
            conns[str(conn)].ack = header['seq_num'] + data_len
            seq = conns[str(conn)].seq
            ack = conns[str(conn)].ack
            tcp_tx(conn, tcp_pkt(conn, flags=16, seq=seq, ack=ack))
            # 将数据递交给应用层
            if data_len > 0:
                app_recv(conn, data)

    elif conns[str(conn)].state == State.FIN_WAIT1:
        # 接收到FIN-ACK
        if flags == 16:
            # 进入FIN_WAIT2阶段
            conns[str(conn)].state = State.FIN_WAIT2
            conns[str(conn)].seq = header['ack_num']
            conns[str(conn)].ack = header['seq_num']
        # 接收到FIN
        elif flags == 17:
            # 通知应用层半关闭
            app_peer_fin(conn)
            # 进入CLOSING
            conns[str(conn)].state = State.CLOSING
            # 回复ACK
            conns[str(conn)].seq = header['ack_num']
            conns[str(conn)].ack = header['seq_num'] + 1
            seq = conns[str(conn)].seq
            ack = conns[str(conn)].ack
            tcp_tx(conn, tcp_pkt(conn, flags=16, seq=seq, ack=ack))

    elif conns[str(conn)].state == State.FIN_WAIT2:
        # 接收到FIN包
        if flags == 17:
            # 通知应用层半关闭
            app_peer_fin(conn)
            # 回复ACK
            conns[str(conn)].seq = header['ack_num']
            conns[str(conn)].ack = header['seq_num'] + 1
            seq = conns[str(conn)].seq
            ack = conns[str(conn)].ack
            tcp_tx(conn, tcp_pkt(conn, flags=16, seq=seq, ack=ack))
            # 进入TIME-WAIT阶段
            conns[str(conn)].state = State.TIMEWAIT
            # 倒计时
            time_left = 10
            while time_left > 0:
                print('倒计时(s):', time_left)
                time.sleep(1)
                time_left = time_left - 1
            # 关闭连接，通知应用层释放资源
            conns.pop(str(conn))
            release_connection(conn)


    elif conns[str(conn)].state == State.CLOSING:
        # 接收到FIN-ACK
        if flags == 16:
            # 进入TIME-WAIT阶段
            conns[str(conn)].state = State.TIMEWAIT
            # 倒计时
            time_left = 10
            while time_left > 0:
                print('倒计时(s):', time_left)
                time.sleep(1)
                time_left = time_left - 1
            # 关闭连接，通知应用层释放资源
            conns.pop(str(conn))
            release_connection(conn)

    elif conns[str(conn)].state == State.TIMEWAIT:
        pass

    elif conns[str(conn)].state == State.CLOSE_WAIT:
        pass

    elif conns[str(conn)].state == State.LAST_ACK:
        # 接收到FIN-ACK
        if flags == 16:
            # 进入TIME-WAIT阶段
            conns[str(conn)].state = State.TIMEWAIT
            # 倒计时
            time_left = 10
            while time_left > 0:
                print('倒计时(s):', time_left)
                time.sleep(1)
                time_left = time_left - 1
            # 关闭连接，通知应用层释放资源
            conns.pop(str(conn))
            release_connection(conn)

    print("tcp_rx", conn, data.decode(errors='replace'))


def tick():
    """
    这个函数会每至少100ms调用一次，以保证控制权可以定期的回到你实现的函数中，而不是一直阻塞在main文件里面。
    它可以被用来在不开启多线程的情况下实现超时重传等功能，详见主仓库的README.md
    """
    # TODO 可实现此函数，也可不实现
    pass


def parse_tcp_header(header: bytes):
    '''
    解析TCP报头
    :param header:
    :return:
    '''
    line1 = struct.unpack('>HH', header[:4])
    src_port = line1[0]
    dst_port = line1[1]

    line2 = struct.unpack('>L', header[4:8])
    seq = line2[0]

    line3 = struct.unpack('>L', header[8:12])
    ack = line3[0]

    # 第四行：4bit报头长度 6bit保留位 6bit标志位 16bit窗口大小
    line4 = struct.unpack('>BBH', header[12:16])
    header_length = line4[0] >> 4
    flags = line4[1] & int(b'00111111', 2)
    FIN = line4[1] & 1
    SYN = (line4[1] >> 1) & 1
    RST = (line4[1] >> 2) & 1
    PSH = (line4[1] >> 3) & 1
    ACK = (line4[1] >> 4) & 1
    URG = (line4[1] >> 5) & 1
    window_size = line4[2]

    line5 = struct.unpack('>HH', header[16:20])
    tcp_checksum = line5[0]
    urg_ptr = line5[1]

    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'seq_num': seq,
        'ack_num': ack,
        'header_length': header_length,
        'flags': flags,
        'flag': {
            'FIN': FIN,
            'SYN': SYN,
            'RST': RST,
            'PSH': PSH,
            'ACK': ACK,
            'URG': URG
        },
        'window_size': window_size,
        'tcp_checksum': tcp_checksum,
        'urg_ptr': urg_ptr
    }

def tcp_pkt(conn, flags, seq, ack, data=None):
    '''
    创建TCP报文
    :param conn:    连接状态
    :param flags:   标签
    :param seq:     序列号
    :param ack:     ACK
    :param data:    数据
    :return:  bytes数组
    '''
    if data == None:
        pkt = IP(src=conn["src"]["ip"],
                 dst=conn["dst"]["ip"]) / TCP(dport=conn["dst"]["port"],
                                              sport=conn["src"]["port"],
                                              flags=flags, seq=seq, ack=ack)
        pkt = raw(pkt)[20:40]
    else:
        pkt = IP(src=conn["src"]["ip"],
                 dst=conn["dst"]["ip"]) / TCP(dport=conn["dst"]["port"],
                                              sport=conn["src"]["port"],
                                              flags=flags, seq=seq, ack=ack) / data
        pkt = raw(pkt)[20:]
    return pkt

# 计算checksum（经典算法）
if struct.pack("H", 1) == b"\x00\x01":  # big endian
    checksum_endian_transform = lambda chk: chk
else:
    checksum_endian_transform = lambda chk: ((chk >> 8) & 0xff) | chk << 8

def checksum(pkt):
    if len(pkt) % 2 == 1:
        pkt += b"\0"
    s = sum(array("H", pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    return checksum_endian_transform(s) & 0xffff