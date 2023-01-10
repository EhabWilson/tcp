"""
这是等待你完成的代码。正常情况下，本文件是你唯一需要改动的文件。
你可以任意地改动此文件，改动的范围当然不限于已有的五个函数里。（只要已有函数的签名别改，要是签名改了main里面就调用不到了）
在开始写代码之前，请先仔细阅读此文件和api文件。这个文件里的五个函数是等你去完成的，而api里的函数是供你调用的。
提示：TCP是有状态的协议，因此你大概率，会需要一个什么样的数据结构来记录和维护所有连接的状态
"""
from api import *
import random
import struct
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
    syn_pkt = IP(src=conn["src"]["ip"], dst=conn["dst"]["ip"])/TCP(dport=conn["dst"]["port"], sport=conn["src"]["port"], flags=2, seq=seq)
    syn_pkt = raw(syn_pkt)
    tcp_tx(conn, syn_pkt)

    print("app_connect", conn)


def app_send(conn: ConnectionIdentifier, data: bytes):
    """
    当应用层想要在一个已经建立好的连接上发送数据时，会调用此函数。
    :param conn: 连接对象
    :param data: 数据内容，是字节数组
    :return:
    """
    # 发送报文
    src_port = conn["src"]["port"]
    dst_port = conn["dst"]["port"]
    seq = conns[str(conn)].seq
    ack = conns[str(conn)].seq

    data = b''
    tcp_tx(conn, data)

    print("app_send", conn, data.decode(errors='replace'))


def app_fin(conn: ConnectionIdentifier):
    """
    当应用层想要半关闭连接(FIN)时，会调用此函数。
    :param conn: 连接对象
    :return: 
    """
    # TODO 请实现此函数
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

    if conns[str(conn)].state == State.CLOSED:
        pass
    elif conns[str(conn)].state == State.SYN_SENT:
        # 收到SYN-ACK，回复ACK，完成三次握手
        if flags['SYN'] == 1 and flags['ACK'] == 1:
            conns[str(conn)].state = State.ESTABISHED
            conns[str(conn)].seq = conns[str(conn)].seq + 1
            conns[str(conn)].ack = header['seq_num'] + 1
            seq = conns[str(conn)].seq
            ack = conns[str(conn)].ack
            ack_pkt = IP(src=conn["src"]["ip"], dst=conn["dst"]["ip"])/TCP(dport=conn["dst"]["port"], sport=conn["src"]["port"], flags=16, seq=seq, ack=ack)
            ack_pkt = raw(ack_pkt)
            tcp_tx(conn, ack_pkt)
    elif conns[str(conn)].state == State.ESTABISHED:
        app_recv(conn, data)
    elif conns[str(conn)].state == State.FIN_WAIT1:
        if flags['SYN'] == 1 and flags['ACK'] == 1:

    elif conns[str(conn)].state == State.FIN_WAIT2:
        # TODO
    elif conns[str(conn)].state == State.CLOSING:
        # TODO
    elif conns[str(conn)].state == State.TIMEWAIT:
        # TODO


    print("tcp_rx", conn, data.decode(errors='replace'))


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
    header_length = line4[0]
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
        'flags': {
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