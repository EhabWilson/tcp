/// 这是driver部分的源代码。不得改动！
/// driver的作用是与复杂的内核网络栈、IP转发链进行交互，得对外的连接能够被捕获并转发给你的TCP协议栈。
/// 你不可以改动driver的源代码。助教在评判你的作业的时候，也会使用自己编译的driver，不会使用你提交的driver。
/// 但是，你可以自由地阅读和分析driver的源代码。如果你认为有有问题的地方，请随时找助教反应。
use std::collections::{HashMap, HashSet};
use std::ffi::{c_void, CString};
use std::fs::remove_file;
use std::io::Error;
use std::mem::size_of;
use std::net::{IpAddr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::str::FromStr;

use anyhow::anyhow;
use anyhow::Result;
use bson::spec::BinarySubtype;
use clap::{Parser, Subcommand};
use lazy_static::lazy_static;
use pnet_packet::Packet;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket, UnixDatagram};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep, timeout};

use crate::nftables::{clear_all, NftGuard, print_all};

mod nftables;

#[derive(PartialEq, Eq, Hash, Clone, Debug, Serialize, Deserialize)]
pub struct IpAndPort {
    pub ip: String,
    pub port: u16,
}

#[derive(PartialEq, Eq, Hash, Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionIdentifier {
    pub src: IpAndPort,
    pub dst: IpAndPort,
}

#[derive(Clone, Serialize, Deserialize)]
struct Event<'a> {
    conn: ConnectionIdentifier,
    bytes: &'a [u8],
    flags: u32,
}

fn libc_wrap(retcode: libc::c_int) -> Result<libc::c_int, Error> {
    if retcode == -1 { Err(Error::last_os_error()) } else { Ok(retcode) }
}

fn create_raw_sock() -> std::io::Result<UdpSocket> {
    let std_sock = unsafe {
        let fd = libc_wrap(libc::socket(libc::PF_INET, libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, libc::IPPROTO_TCP))?;
        libc_wrap(libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_MARK, &86 as *const i32 as *const c_void, size_of::<i32>() as libc::socklen_t))?;
        std::net::UdpSocket::from_raw_fd(fd)
    };
    UdpSocket::from_std(std_sock)
}

type AppSocksType = HashMap<ConnectionIdentifier, (OwnedWriteHalf, u8, RawFd)>;

lazy_static! {
    static ref APP_SOCKS: Mutex<AppSocksType> = Mutex::new(HashMap::new()); // u8: 0x20读端开启， 0x10写端开启；0x1 incoming（尚未实现），0x0 outgoing
    static ref RAW_SOCK: UdpSocket = create_raw_sock().unwrap();
    static ref UNIX_SOCK: UnixDatagram = (|| {
        remove_file("/tmp/network-exp4-driver.socket").ok();
        let sock = UnixDatagram::bind("/tmp/network-exp4-driver.socket").unwrap();
        let cstring = CString::new("/tmp/network-exp4-driver.socket").unwrap();
        unsafe { libc_wrap(libc::chmod(cstring.as_ptr(), 0x777)).unwrap(); }
        sock
    })();
    static ref KEEP_ALIVE_SWITCH: Mutex<bool> = Mutex::new(false);
}

fn get_connection_identifier(app_socks: &AppSocksType, addr: &SocketAddr, tcp_packet: &[u8]) -> Option<ConnectionIdentifier> {
    let tcp_packet_obj = pnet_packet::tcp::TcpPacket::new(tcp_packet)?;
    let dst_ip = addr.ip().to_string();
    let src_port = tcp_packet_obj.get_destination();
    let dst_port = tcp_packet_obj.get_source();
    for (k, _) in app_socks {
        if k.src.port == src_port && k.dst.port == dst_port && k.dst.ip == dst_ip {
            return Some(k.clone());
        }
    }
    None
}

async fn process_raw_sock_inner(buf: &mut [u8]) -> Result<()> {
    let (size, addr) = RAW_SOCK.recv_from(buf).await?;
    if size >= buf.len() { return Err(anyhow!("WARNING: 收到了超过接收buffer大小({})的IP raw报文！该报文并未被完整接收！", buf.len())); }
    let ip_packet = pnet_packet::ipv4::Ipv4Packet::new(buf).ok_or(anyhow!("Received packet cannot be parsed as IPV4"))?;
    let tcp_packet: &[u8] = ip_packet.payload();
    let conn_res;
    {
        conn_res = get_connection_identifier(APP_SOCKS.lock().await.deref(), &addr, tcp_packet);
    }
    if let Some(conn) = conn_res {
        driver_event(&conn, tcp_packet, 0x40).await;
    }
    Ok(())
}

async fn process_raw_sock() {
    // 监听(recv)raw_sock上的所有数据，发现匹配的数据，就rx
    let mut buf = [0u8; 500000];
    loop {
        if let Err(e) = process_raw_sock_inner(&mut buf).await {
            eprintln!("process_raw_sock_inner FAILED: {e}")
        }
    }
}

async fn process_unix_sock_inner(buf: &mut [u8]) -> Result<()> {
    let size = UNIX_SOCK.recv(buf).await?;
    if size >= buf.len() { return Err(anyhow!("WARNING: 收到了超过接收buffer大小({})的unix domain socket报文！该报文并未被完整接收！", buf.len())); }
    let event = bson::from_slice::<Event>(&buf[0..size])?;
    if let Err(e) = sdk_event(&event.conn, event.bytes, event.flags).await { eprintln!("sdk_event FAILED: {e}") }
    Ok(())
}

async fn process_unix_sock() {
    let mut buf = [0u8; 500000];
    loop {
        if let Err(e) = process_unix_sock_inner(&mut buf).await {
            eprintln!("process_unix_sock_inner FAILED: {e}")
        }
    }
}

fn on_app_sock_error(map: &mut AppSocksType, conn: &ConnectionIdentifier) {
    // 与应用层断联(系统调用返回错误)，一律视为应用层要求rst
    map.remove(conn);
    let conn_2 = conn.clone();
    tokio::spawn(async move {
        driver_event(&conn_2, &[], 0x4).await
    });
}

/// flags: 0x4 rst(并release资源), 0x2 syn, 0x1 fin
/// 0x0时是recv到数据。0x40时是发送RAW的TCP报文。
/// 0x80单纯release资源。0xa0是新开连接，release全部connection
async fn sdk_event(conn: &ConnectionIdentifier, bytes: &[u8], flags: u32) -> Result<()> {
    if flags == 0x80 {
        APP_SOCKS.lock().await.remove(&conn);
    } else if flags == 0xa0 {
        // 验证通信内容是否正确，不正确，直接panic
        if !(conn.src.ip == "127.84.0.1" && conn.src.port == 8484 && std::str::from_utf8(bytes) == Ok("network_exp4")) { panic!("错误的客户端握手消息！") }
        // 移除全部connection
        APP_SOCKS.lock().await.clear();
        UNIX_SOCK.connect("/tmp/network-exp4-sdk.socket")?;
        *KEEP_ALIVE_SWITCH.lock().await = true;
        println!("已与新启动的TCP协议实现程序建立通信。先前捕获的TCP连接(如有)均已释放。")
    } else if flags == 0x2 {
        // 设置flag，从而在（至多50ms后）负责read的协程开始读数据
        if let Some((_, sock_flag, _)) = APP_SOCKS.lock().await.get_mut(&conn) {
            *sock_flag = *sock_flag | 0x4;
        }
    } else if flags == 0x4 {
        // 强行关闭文件描述符，然后移除连接
        let mut map = APP_SOCKS.lock().await;
        if let Some((_, _, fd)) = map.get_mut(&conn) {
            unsafe { libc::close(*fd); }
        }
        map.remove(&conn);
    } else if flags == 0x1 {
        // TcpStream W端 shutdown
        let mut map = APP_SOCKS.lock().await;
        if let Some((writer, _, _)) = map.get_mut(&conn) {
            if let Err(_) = writer.shutdown().await {
                on_app_sock_error(map.deref_mut(), &conn);
            }
        }
    } else if flags == 0x0 {
        let mut map = APP_SOCKS.lock().await;
        let mut sent = 0;
        if let Some((writer, _, _)) = map.get_mut(&conn) {
            while sent < bytes.len() {
                match writer.write(&bytes[sent..]).await {
                    Ok(size) => {
                        sent += size;
                    }
                    Err(_) => {
                        on_app_sock_error(map.deref_mut(), &conn);
                        break;
                    }
                }
            }
        }
    } else if flags == 0x40 {
        let addr = SocketAddr::new(IpAddr::from_str(&conn.dst.ip)?, 0);
        RAW_SOCK.send_to(&bytes, addr).await?;
    }
    Ok(())
}

async fn driver_event_inner(event: Event<'_>) -> Result<()> {
    let mut bson_obj = bson::to_document(&event)?;
    bson_obj.insert("bytes", bson::Binary { subtype: BinarySubtype::Generic, bytes: Vec::from(event.bytes) });
    let data = bson::to_vec(&bson_obj)?;
    UNIX_SOCK.send(&data[..]).await?;
    Ok(())
}

/// flags: 0x4 rst(并release资源), 0x2 connected, 0x1 fin。
/// 0x0时是要send数据。0x40时是收到了RAW的TCP报文。
async fn driver_event(conn: &ConnectionIdentifier, bytes: &[u8], flags: u32) {
    let event = Event { conn: conn.clone(), bytes: bytes, flags };
    if let Err(e) = driver_event_inner(event).await {
        eprintln!("driver_event FAILED: {e}")
    }
}

async fn read_app_socket(conn: ConnectionIdentifier, mut reader: OwnedReadHalf) {
    let mut buf = [0u8; 3000];
    let mut flags = 0;
    loop {
        let mut read_res = Err(anyhow!(""));
        if flags & 0x4 == 0x4 {
            // 读数据。读的时候不能死读。读到一定时间没有结果，就放弃并检查字典状态
            read_res = timeout(Duration::from_millis(500), reader.read(&mut buf)).await.or_else(|_| Err(anyhow!("")));
        } else {
            // 不读数据，睡50ms
            sleep(Duration::from_millis(50)).await;
        }
        // 加锁，拿socket对象，读flags。拿完后立刻放锁。如果拿不到，说明已被强制销毁，直接break。
        {
            if let Some((_, flag, _)) = APP_SOCKS.lock().await.get_mut(&conn) {
                flags = *flag
            } else {
                break;
            }
        }
        if let Ok(r) = read_res {
            // 尝试读数据了，也读到了（没超时）
            if let Ok(size) = r {
                if size > 0 {
                    driver_event(&conn, &buf[0..size], 0x0).await;
                } else {
                    driver_event(&conn, &[], 0x1).await;
                    break;
                }
            } else {
                on_app_sock_error(APP_SOCKS.lock().await.deref_mut(), &conn);
                break;
            }
        }
    }
}

async fn get_available_pool_port(dst: &IpAndPort) -> Result<u16> {
    let port_range = 61084u16..65084u16;
    let mut available_ports = Vec::new();

    let used_ports: HashSet<u16> = HashSet::from_iter(APP_SOCKS.lock().await.keys().filter(|&conn| conn.dst == *dst).map(|conn| conn.src.port));
    for port in port_range {
        if !used_ports.contains(&port) { available_ports.push(port) };
    }
    if available_ports.len() > 0 {
        let randval = rand::thread_rng().gen_range(0..available_ports.len());
        Ok(available_ports[randval])
    } else {
        Err(anyhow!("Connection Source Port Poll is full!"))
    }
}

async fn process_listener_inner(listener: &TcpListener, flags: u8) -> Result<()> {
    let (socket, _) = listener.accept().await?;
    // 构造ConnectionIdentifier对象，然后把socket所有权转移到APP_SOCKS里面去
    let dst = IpAndPort { ip: socket.local_addr()?.ip().to_string(), port: socket.local_addr()?.port() };
    let conn = ConnectionIdentifier { src: IpAndPort { ip: socket.peer_addr()?.ip().to_string(), port: get_available_pool_port(&dst).await? }, dst };
    println!("捕获到新连接！从 本机:{} 到 {} 。(被捕获连接原始来源 {} )", conn.src.port, socket.local_addr()?, socket.peer_addr()?);
    let fd = socket.as_raw_fd();
    let (reader, writer) = socket.into_split();
    {
        APP_SOCKS.lock().await.insert(conn.clone(), (writer, flags | 0x30, fd)); // 0x30是读写端均有效的标志
    }
    tokio::spawn(read_app_socket(conn.clone(), reader));
    if flags & 0x1 == 0x0 {
        driver_event(&conn, &[], 0x2).await;
    };
    Ok(())
}

async fn process_listener(listener: TcpListener, flags: u8) {
    unsafe {
        libc_wrap(libc::setsockopt(listener.as_raw_fd(), libc::SOL_IP, libc::IP_TRANSPARENT, &1 as *const i32 as *const c_void, size_of::<i32>() as libc::socklen_t)).unwrap();
    }
    loop {
        if let Err(e) = process_listener_inner(&listener, flags).await {
            eprintln!("process_listener_inner FAILED: {e}")
        }
    }
}

async fn unix_sock_keepalive() {
    let data = [0u8];
    loop {
        sleep(Duration::from_millis(500)).await;
        if *KEEP_ALIVE_SWITCH.lock().await == true {
            if let Err(_) = UNIX_SOCK.send(&data).await { // 发送一字节的数据以保活
                *KEEP_ALIVE_SWITCH.lock().await = false;
            }
        }
    }
}

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// 从本机发出的所有TCP连接都会被捕获和调用自定义TCP协议。不带任何command时，默认即为此模式。
    All,
    /// 只有从127.84.x.x上发出的TCP连接才会被捕获和调用自定义TCP协议。
    Partial,
    /// 强制清除连接捕获配置后直接退出。正常情况下，程序退出时会自动清除连接捕获配置，但不排除在少数情况下程序异常退出、连接捕获配置没有被清除，造成无法上网等问题。此种情况下，请使用此命令手动清除一次。
    Clear,
    /// 打印当前的连接捕获配置信息。（主要供driver开发者调试用）
    Print,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let command = cli.command;
    match command {
        Some(Commands::Clear) => {
            clear_all();
            return Ok(());
        }
        Some(Commands::Print) => {
            print_all();
            return Ok(());
        }
        _ => {}
    }

    let listener1 = TcpListener::bind("127.0.0.1:21184").await?;
    tokio::spawn(process_raw_sock());
    tokio::spawn(process_unix_sock());
    tokio::spawn(unix_sock_keepalive());
    // 在确保listener监听成功后，再配置nftables规则
    let nftguard = NftGuard::new(if let Some(Commands::Partial) = command { false } else { true });
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        drop(nftguard);
        std::process::exit(1);
    });
    process_listener(listener1, 0x0).await;
    Ok(())
}
