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
from threading import Timer
from datetime import datetime
from array import array
from typing import Dict
from enum import Enum, unique
from scapy.all import raw
from scapy.layers.inet import IP, TCP


@unique
class State(Enum):
    CLOSED = 0
    # LITSEN          = 1
    SYN_SENT = 2
    ESTABISHED = 3
    FIN_WAIT1 = 4
    FIN_WAIT2 = 5
    CLOSING = 6
    TIMEWAIT = 7
    CLOSE_WAIT = 8
    LAST_ACK = 9


# 连接状态
class Connection(object):
    def __init__(self, state: str, seq: int, ack: int):
        self.state = state
        self.seq = seq
        self.ack = ack

        self.sendbase = seq
        self.base_cycle = 0


conns: Dict[str, Connection] = {}
RTO = 500    # ms
CloseTime = 10          # s
records: Dict[str, tuple] = {}


def app_connect(conn: ConnectionIdentifier):
    """
    当有应用想要发起一个新的连接时，会调用此函数。想要连接的对象在conn里提供了。
    你应该向想要连接的对象发送SYN报文，执行三次握手的逻辑。
    当连接建立好后，你需要调用app_connected函数，通知应用层连接已经被建立好了。
    :param conn: 连接对象
    :return:
    """
    # 创建连接记录
    seq = random.randint(1, 1 << 32 - 1)
    conns[str(conn)] = Connection(State.CLOSED, seq, 0)

    # 发送SYN报文
    pkt = tcp_pkt(conn, flags=2, seq=seq, ack=0)
    tcp_tx(conn, pkt)

    # 超时重传检测
    check = Timer(RTO / 1000, retransmit_check, (conn, pkt, seq))
    check.start()
    # records[datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')] = (conn, seq, pkt)
    conns[str(conn)].seq = conns[str(conn)].seq + 1

    # 进入SYN-SENT状态
    conns[str(conn)].state = State.SYN_SENT

    print("app_connect", conn)
    print(conns[str(conn)].state, "\n")


def app_send(conn: ConnectionIdentifier, data: bytes):
    """
    当应用层想要在一个已经建立好的连接上发送数据时，会调用此函数。
    :param conn: 连接对象
    :param data: 数据内容，是字节数组
    :return:
    """
    # 发送报文
    if conns[str(conn)] != State.CLOSED:
        seq = conns[str(conn)].seq
        ack = conns[str(conn)].ack
        pkt = tcp_pkt(conn, flags=24, seq=seq, ack=ack, data=data)
        tcp_tx(conn, pkt)
        check = Timer(RTO / 1000, retransmit_check, (conn, pkt, seq))
        check.start()
        # records[datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')] = (conn, seq, pkt)
        conns[str(conn)].seq = conns[str(conn)].seq + len(data)

        print("app_send", conn)  # , data.decode(errors='replace'))
        print("len of data: {}".format(len(data)))
        print(conns[str(conn)].state, "\n")


def app_fin(conn: ConnectionIdentifier):
    """
    当应用层想要半关闭连接(FIN)时，会调用此函数。
    :param conn: 连接对象
    :return:
    """
    # 发送FIN报文
    seq = conns[str(conn)].seq
    ack = conns[str(conn)].ack
    pkt = tcp_pkt(conn, flags=17, seq=seq, ack=ack)
    tcp_tx(conn, pkt)
    check = Timer(RTO / 1000, retransmit_check, (conn, pkt, seq))
    check.start()
    # records[datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')] = (conn, seq, pkt)
    conns[str(conn)].seq = conns[str(conn)].seq + 1

    # 改变状态
    conns[str(conn)].state = State.FIN_WAIT1

    print("app_fin", conn)
    print(conns[str(conn)].state, "\n")


def app_rst(conn: ConnectionIdentifier):
    """
    当应用层想要重置连接(RES)时，会调用此函数
    :param conn: 连接对象
    :return:
    """
    # TODO 请实现此函数
    seq = conns[str(conn)].seq
    ack = conns[str(conn)].ack
    pkt = tcp_pkt(conn, flags=20, seq=seq, ack=ack)
    tcp_tx(conn, pkt)
    check = Timer(RTO / 1000, retransmit_check, (conn, pkt, seq))
    check.start()
    print("app_rst", conn)


def tcp_rx(conn: ConnectionIdentifier, data: bytes):
    """
    当收到TCP报文时，会调用此函数。
    正常情况下，你会对TCP报文，根据报文内容和连接的当前状态加以处理，然后调用0个~多个api文件中的函数
    :param conn: 连接对象
    :param data: TCP报文内容，是字节数组。（含TCP报头，不含IP报头）
    :return:
    """
    header = parse_tcp_header(data[:20])
    flags = header['flags']

    # 对端要求重置连接
    if flags == 20:
        app_peer_rst(conn)

    # 连接未建立或已关闭时
    elif conns.get(str(conn)) is None or conns[str(conn)].state == State.CLOSED:
        app_rst(conn)

    # 其余情况根据当前状态进行处理
    elif conns[str(conn)].state == State.SYN_SENT:
        # 收到SYN-ACK
        if flags == 18:
            # 回复ACK
            if conns[str(conn)].sendbase > header['ack_num']:
                conns[str(conn)].base_cycle += 1
            conns[str(conn)].sendbase = header['ack_num']
            conns[str(conn)].ack = header['seq_num'] + 1
            seq = conns[str(conn)].seq
            ack = conns[str(conn)].ack
            tcp_tx(conn, tcp_pkt(conn, flags=16, seq=seq, ack=ack))
            print("ACK")
            # 通知应用层
            app_connected(conn)
            # 完成三次握手，进入ESTABLISHED阶段
            conns[str(conn)].state = State.ESTABISHED

    elif conns[str(conn)].state == State.ESTABISHED:
        print("data_len: {}  header_len: {}  flags: {}".format(len(data), header['header_length'], flags))
        # 情形1：收到FIN报文
        if flags == 17:
            # 回复ACK
            if conns[str(conn)].sendbase > header['ack_num']:
                conns[str(conn)].base_cycle += 1
            conns[str(conn)].sendbase = header['ack_num']
            conns[str(conn)].ack = header['seq_num'] + 1
            seq = conns[str(conn)].seq
            ack = conns[str(conn)].ack
            tcp_tx(conn, tcp_pkt(conn, flags=16, seq=seq, ack=ack))
            print("ACK")
            # 进入CLOSE_WAIT阶段
            conns[str(conn)].state = State.CLOSE_WAIT
            # 通知应用层半关闭
            app_peer_fin(conn)
            # 发送FIN报文
            seq = conns[str(conn)].seq
            ack = conns[str(conn)].ack
            pkt = tcp_pkt(conn, flags=17, seq=seq, ack=ack)
            tcp_tx(conn, pkt)
            print("FIN")
            check = Timer(RTO / 1000, retransmit_check, (conn, pkt, seq))
            check.start()
            # records[datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')] = (conn, seq, pkt)
            conns[str(conn)].seq = conns[str(conn)].seq + 1
            # 进入LAST_ACK阶段
            conns[str(conn)].state = State.LAST_ACK
        # 情形2：收到数据/ACK
        else:
            if conns[str(conn)].sendbase > header['ack_num']:
                conns[str(conn)].base_cycle += 1
            # 计算数据长度
            conns[str(conn)].sendbase = header['ack_num']
            data_len = len(data) - header['header_length'] * 4
            if data_len > 0:
                # 回复ACK
                if conns[str(conn)].ack == header['seq_num']:
                    conns[str(conn)].ack = header['seq_num'] + data_len
                seq = conns[str(conn)].seq
                ack = conns[str(conn)].ack
                tcp_tx(conn, tcp_pkt(conn, flags=16, seq=seq, ack=ack))
                print("ACK")
                # 将数据递交给应用层
                app_recv(conn, data[header['header_length'] * 4:])

    elif conns[str(conn)].state == State.FIN_WAIT1:
        # 接收到FIN-ACK
        if flags == 16:
            # 进入FIN_WAIT2阶段
            if conns[str(conn)].sendbase > header['ack_num']:
                conns[str(conn)].base_cycle += 1
            conns[str(conn)].state = State.FIN_WAIT2
            conns[str(conn)].sendbase = header['ack_num']
            conns[str(conn)].ack = header['seq_num']
        # 接收到FIN
        elif flags == 17:
            # 通知应用层半关闭
            app_peer_fin(conn)
            # 进入CLOSING
            conns[str(conn)].state = State.CLOSING
            # 回复ACK
            if conns[str(conn)].sendbase > header['ack_num']:
                conns[str(conn)].base_cycle += 1
            conns[str(conn)].sendbase = header['ack_num']
            conns[str(conn)].ack = header['seq_num'] + 1
            seq = conns[str(conn)].seq
            ack = conns[str(conn)].ack
            tcp_tx(conn, tcp_pkt(conn, flags=16, seq=seq, ack=ack))
            print("ACK")

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
            print("ACK")
            # 进入TIME-WAIT阶段
            conns[str(conn)].state = State.TIMEWAIT
            # 倒计时
            close_timer = Timer(CloseTime, close_connection, (conn,))
            close_timer.start()

    elif conns[str(conn)].state == State.CLOSING:
        # 接收到FIN-ACK
        if flags == 16:
            # 进入TIME-WAIT阶段
            conns[str(conn)].state = State.TIMEWAIT
            # 倒计时
            close_timer = Timer(CloseTime, close_connection, (conn,))
            close_timer.start()

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
            close_connection(conn)

    print("tcp_rx", conn)  # , data.decode(encoding='UTF-8',errors='replace'))
    print(conns[str(conn)].state, "\n")


def tick():
    """
    这个函数会每至少100ms调用一次，以保证控制权可以定期的回到你实现的函数中，而不是一直阻塞在main文件里面。
    它可以被用来在不开启多线程的情况下实现超时重传等功能，详见主仓库的README.md
    """
    # TODO 可实现此函数，也可不实现
    pass


def parse_tcp_header(header: bytes):
    """
    解析TCP报头
    :param header:
    :return:
    """
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
    """
    创建TCP报文
    :param conn:    连接状态
    :param flags:   标签
    :param seq:     序列号
    :param ack:     ACK
    :param data:    数据
    :return:  bytes数组
    """
    if data is None:
        pkt = IP(src=conn["src"]["ip"],
                 dst=conn["dst"]["ip"]) / TCP(dport=conn["dst"]["port"],
                                              sport=conn["src"]["port"],
                                              flags=flags, seq=seq, ack=ack, window=65535)
        pkt = raw(pkt)[20:40]
    else:
        pkt = IP(src=conn["src"]["ip"],
                 dst=conn["dst"]["ip"]) / TCP(dport=conn["dst"]["port"],
                                              sport=conn["src"]["port"],
                                              flags=flags, seq=seq, ack=ack, window=65535) / data
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


def close_connection(conn):
    release_connection(conn)
    conns[str(conn)].state = State.CLOSED


def retransmit_check(conn, pkt, seq, times=1):
    """
    检测是否需要超时重传
    :param conn:
    :param pkt:
    :param seq:
    :return:
    """
    if conns[str(conn)].state == State.CLOSED:
        return

    if (conns[str(conn)].sendbase + (1 << 32) * conns[str(conn)].base_cycle) <= seq:
        if times <= 5:
            with open('record.txt', 'a+') as f:
                f.write("retrans: {} {}  times: {}\n".format(conns[str(conn)].sendbase, seq, times))
            tcp_tx(conn, pkt)
            check = Timer(RTO / 1000 * 2 ** (times - 1), retransmit_check, (conn, pkt, seq, times + 1))
            check.start()
        # 重传超过5次时，自主重置连接并告知应用层
        else:
            conns[str(conn)].state = State.CLOSED
            app_rst(conn)
            app_peer_rst(conn)
    else:
        with open('record.txt', 'a+') as f:
            f.write("no retrans: {} {}\n".format(conns[str(conn)].sendbase, seq))
