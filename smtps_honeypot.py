import socket
import ssl
import threading
import logging
import datetime
import os
import argparse
import time
import json
import hashlib
import binascii
import select
from typing import Tuple, Optional, Dict, List, Set
import email
import email.policy
from email.parser import BytesParser
import base64
import quopri
# 设置日志配置
def setup_logging(log_dir: str, debug: bool = False) -> None:
    """配置日志输出到文件和控制台"""
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_file = os.path.join(log_dir, f"smtps_listener_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    # Configure root logger
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

# 创建会话ID
def generate_session_id(client_address: Tuple[str, int], timestamp: datetime.datetime) -> str:
    """生成唯一的会话ID"""
    session_data = f"{client_address[0]}:{client_address[1]}:{timestamp.isoformat()}"
    return hashlib.md5(session_data.encode()).hexdigest()[:12]

# 记录TLS流量到单个文件
def log_tls_traffic(traffic_dir: str, session_id: str, client_address: Tuple[str, int], 
                   data: bytes, direction: str, tls_info: Dict = None) -> None:
    """记录TLS流量到单个文件"""
    if not os.path.exists(traffic_dir):
        os.makedirs(traffic_dir)
    
    timestamp = datetime.datetime.now()
    client_ip, client_port = client_address
    
    # 确保tls目录存在
    tls_dir = os.path.join(traffic_dir, "tls")
    if not os.path.exists(tls_dir):
        os.makedirs(tls_dir)
        
    # 创建单个TLS流量记录文件
    tls_log_file = os.path.join(tls_dir, "tls_traffic.log")
    
    # 也保存原始数据
    raw_dir = os.path.join(tls_dir, "raw_data")
    if not os.path.exists(raw_dir):
        os.makedirs(raw_dir)
    
    # 保存原始数据到文件
    raw_filename = f"{session_id}_{timestamp.strftime('%Y%m%d_%H%M%S_%f')}_{direction}.bin"
    raw_filepath = os.path.join(raw_dir, raw_filename)
    
    with open(raw_filepath, 'wb') as f:
        f.write(data)
    
    # 记录TLS流量详情到日志文件
    with open(tls_log_file, 'a') as f:
        f.write(f"============ TLS 流量 ============\n")
        f.write(f"会话ID: {session_id}\n")
        f.write(f"时间: {timestamp.isoformat()}\n")
        f.write(f"客户端: {client_ip}:{client_port}\n")
        f.write(f"方向: {direction}\n")
        f.write(f"数据大小: {len(data)} 字节\n")
        
        # 添加TLS信息（如果有）
        if tls_info:
            f.write(f"TLS版本: {tls_info.get('version', 'Unknown')}\n")
            f.write(f"加密套件: {tls_info.get('cipher', 'Unknown')}\n")
            f.write(f"密钥长度: {tls_info.get('bits', 'Unknown')}\n")
        
        # 尝试解码数据（如果是文本）
        try:
            decoded = data.decode('utf-8', errors='replace')
            f.write(f"数据内容: {decoded.strip()}\n")
        except:
            # 如果无法解码为文本，记录十六进制表示
            f.write(f"二进制数据: {binascii.hexlify(data[:64]).decode()} (前64字节)\n")
            f.write(f"原始文件: {raw_filepath}\n")
        
        f.write(f"原始文件: {raw_filepath}\n")
        f.write("-" * 50 + "\n\n")
    
    logging.debug(f"记录了 {len(data)} 字节的 {direction} TLS流量")

# 记录原始TLS流量
def log_raw_tls_traffic(traffic_dir: str, session_id: str, client_address: Tuple[str, int], 
                       data: bytes, direction: str) -> None:
    """记录未解密的原始TLS流量"""
    if not os.path.exists(traffic_dir):
        os.makedirs(traffic_dir)
    
    timestamp = datetime.datetime.now()
    client_ip, client_port = client_address
    
    # 确保raw_tls目录存在
    raw_tls_dir = os.path.join(traffic_dir, "raw_tls")
    if not os.path.exists(raw_tls_dir):
        os.makedirs(raw_tls_dir)
        
    # 创建单个原始TLS流量记录文件
    raw_tls_log_file = os.path.join(raw_tls_dir, "raw_tls_traffic.log")
    
    # 也保存原始数据
    raw_dir = os.path.join(raw_tls_dir, "raw_data")
    if not os.path.exists(raw_dir):
        os.makedirs(raw_dir)
    
    # 保存原始数据到文件
    raw_filename = f"{session_id}_{timestamp.strftime('%Y%m%d_%H%M%S_%f')}_{direction}.bin"
    raw_filepath = os.path.join(raw_dir, raw_filename)
    
    with open(raw_filepath, 'wb') as f:
        f.write(data)
    
    # 记录原始TLS流量详情到日志文件
    with open(raw_tls_log_file, 'a') as f:
        f.write(f"============ 原始TLS流量 ============\n")
        f.write(f"会话ID: {session_id}\n")
        f.write(f"时间: {timestamp.isoformat()}\n")
        f.write(f"客户端: {client_ip}:{client_port}\n")
        f.write(f"方向: {direction}\n")
        f.write(f"数据大小: {len(data)} 字节\n")
        
        # TLS流量通常是二进制数据，记录十六进制表示
        f.write(f"数据(十六进制前64字节): {binascii.hexlify(data[:64]).decode()}\n")
        f.write(f"原始文件: {raw_filepath}\n")
        f.write("-" * 50 + "\n\n")
    
    logging.debug(f"记录了 {len(data)} 字节的 {direction} 原始TLS流量")

# 记录连接尝试到单个文件
def log_connection_attempt(traffic_dir: str, client_address: Tuple[str, int], error_message: str) -> None:
    """记录连接尝试到单个日志文件"""
    if not os.path.exists(traffic_dir):
        os.makedirs(traffic_dir)
    
    timestamp = datetime.datetime.now()
    client_ip, client_port = client_address
    
    # 创建连接日志文件
    log_file = os.path.join(traffic_dir, "connection_attempts.log")
    
    # 写入数据
    with open(log_file, 'a') as f:
        f.write(f"============ 连接尝试 ============\n")
        f.write(f"时间: {timestamp.isoformat()}\n")
        f.write(f"来源: {client_ip}:{client_port}\n")
        f.write(f"错误: {error_message}\n")
        f.write("-" * 50 + "\n\n")
    
    logging.debug(f"记录来自 {client_ip}:{client_port} 的连接尝试")

# 记录非TLS流量
def log_raw_traffic(traffic_dir: str, session_id: str, client_address: Tuple[str, int], data: bytes, direction: str) -> None:
    """记录非TLS原始流量"""
    if not os.path.exists(traffic_dir):
        os.makedirs(traffic_dir)
    
    timestamp = datetime.datetime.now()
    client_ip, client_port = client_address
    
    # 确保raw目录存在
    raw_dir = os.path.join(traffic_dir, "raw")
    if not os.path.exists(raw_dir):
        os.makedirs(raw_dir)
    
    # 创建单个RAW流量记录文件
    raw_log_file = os.path.join(raw_dir, "raw_traffic.log")
    
    # 也保存原始数据
    data_dir = os.path.join(raw_dir, "data")
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    
    # 保存原始数据到文件
    raw_filename = f"{session_id}_{timestamp.strftime('%Y%m%d_%H%M%S_%f')}_{direction}.bin"
    raw_filepath = os.path.join(data_dir, raw_filename)
    
    with open(raw_filepath, 'wb') as f:
        f.write(data)
    
    # 记录流量详情到日志文件
    with open(raw_log_file, 'a') as f:
        f.write(f"============ 原始流量 ============\n")
        f.write(f"会话ID: {session_id}\n")
        f.write(f"时间: {timestamp.isoformat()}\n")
        f.write(f"客户端: {client_ip}:{client_port}\n")
        f.write(f"方向: {direction}\n")
        f.write(f"数据大小: {len(data)} 字节\n")
        
        # 尝试解码数据（如果是文本）
        try:
            decoded = data.decode('utf-8', errors='replace')
            f.write(f"数据内容: {decoded.strip()}\n")
        except:
            # 如果无法解码为文本，记录十六进制表示
            f.write(f"二进制数据: {binascii.hexlify(data[:64]).decode()} (前64字节)\n")
        
        f.write(f"原始文件: {raw_filepath}\n")
        f.write("-" * 50 + "\n\n")
    
    logging.debug(f"记录了 {len(data)} 字节的 {direction} 原始流量")

# 客户端处理器
def handle_client(client_socket: ssl.SSLSocket, client_address: Tuple[str, int], traffic_dir: str) -> None:
    """处理客户端连接"""
    logger = logging.getLogger(f"client_{client_address[0]}_{client_address[1]}")
    logger.info(f"New connection established")
    
    # 生成会话ID
    session_id = generate_session_id(client_address, datetime.datetime.now())
    
    # 获取TLS会话信息
    tls_info = {}
    try:
        cipher = client_socket.cipher()
        if cipher:
            tls_info = {
                "cipher": cipher[0],
                "version": client_socket.version(),
                "bits": cipher[2] if len(cipher) > 2 else "Unknown"
            }
    except Exception as e:
        logger.debug(f"获取TLS信息失败: {str(e)}")

    # 创建邮件存储目录
    mail_dir = os.path.join(traffic_dir, "emails", session_id)
    os.makedirs(mail_dir, exist_ok=True)
    
    try:
        # Send greeting
        greeting = "220 SMTPS Listener Ready\r\n"
        client_socket.send(greeting.encode())
        log_tls_traffic(traffic_dir, session_id, client_address, greeting.encode(), "server_to_client", tls_info)
        data_buffer = bytearray()
        in_data_mode = False
        while True:
            # Receive data from client with timeout
            client_socket.settimeout(60)  # 60秒接收超时
            data = client_socket.recv(8192)
            if not data:
                break
            
            try:
                decoded = data.decode('utf-8', errors='replace')
                logger.info(f"Received: {decoded.strip()}")
                
                # 检查是否进入DATA模式
                if decoded.upper().startswith("DATA"):
                    response = "354 End data with <CR><LF>.<CR><LF>\r\n"
                    client_socket.send(response.encode())
                    log_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                    in_data_mode = True
                    continue
                if in_data_mode and decoded.strip() == ".":
                    in_data_mode = False
                    self.process_email_data(data_buffer, mail_dir, session_id, client_address)
                    data_buffer.clear()
                    response = "250 OK: Message accepted for delivery\r\n"
                    client_socket.send(response.encode())
                    log_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                    continue
                    
            except UnicodeDecodeError:
                logger.info(f"Received binary data of length {len(data)}")
            
            if not in_data_mode:
                try:
                    command = data.decode('utf-8', errors='replace').split(' ')[0].upper().strip()
                except Exception as e:
                    logger.warning(f"Error parsing command: {str(e)}")
                    command = ""
                
                if command == "EHLO" or command == "HELO":
                    response = "250-Hello\r\n"
                    response += "250-SIZE 10240000\r\n"
                    response += "250-AUTH LOGIN PLAIN\r\n"
                    response += "250-STARTTLS\r\n"
                    response += "250 OK\r\n"
                elif command == "MAIL":
                    response = "250 OK\r\n"
                elif command == "RCPT":
                    response = "250 OK\r\n"
                elif command == "DATA":
                    response = "354 End data with <CR><LF>.<CR><LF>\r\n"
                elif command == "QUIT":
                    response = "221 Bye\r\n"
                elif command.endswith("\r\n.\r\n"):
                    response = "250 OK: Message accepted for delivery\r\n"
                else:
                    response = "500 Command not recognized\r\n"
                
                client_socket.send(response.encode())
                log_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                logger.info(f"Sent: {response.strip()}")

                if command == "QUIT":
                    break
                
    except socket.timeout:
        logger.warning(f"Connection timed out")
    except ssl.SSLError as e:
        logger.error(f"SSL error during communication: {str(e)}")
    except Exception as e:
        logger.error(f"Error handling client: {str(e)}")
    finally:
        client_socket.close()
        logger.info("Connection closed")

def process_email_data(self, data_buffer: bytearray, mail_dir: str, session_id: str, client_address: Tuple[str, int]):
    """处理邮件数据并提取附件"""
    logger = logging.getLogger(f"email_processor_{session_id}")
    
    try:
        # 将字节数据转换为字符串
        email_data = data_buffer.decode('utf-8', errors='replace')
        
        # 查找邮件正文开始位置
        data_start = email_data.find("\r\n\r\n") + 4
        if data_start < 4:
            logger.warning("无法找到邮件正文开始位置")
            return
        
        # 解析邮件
        msg = BytesParser(policy=email.policy.default).parsebytes(data_buffer)
        
        # 保存原始邮件
        raw_email_path = os.path.join(mail_dir, "raw_email.eml")
        with open(raw_email_path, 'wb') as f:
            f.write(data_buffer)
        logger.info(f"原始邮件已保存到: {raw_email_path}")
        
        # 提取邮件信息
        email_info = {
            "from": msg['from'],
            "to": msg['to'],
            "subject": msg['subject'],
            "date": msg['date'],
            "attachments": []
        }
        
        # 保存邮件信息
        info_path = os.path.join(mail_dir, "email_info.json")
        with open(info_path, 'w') as f:
            json.dump(email_info, f, indent=2)
        
        # 处理邮件各部分
        attachment_count = 0
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            
            filename = part.get_filename()
            if not filename:
                # 如果不是附件，可能是邮件正文
                content_type = part.get_content_type()
                ext = {
                    'text/plain': '.txt',
                    'text/html': '.html'
                }.get(content_type, '.bin')
                
                filename = f"body_{content_type.replace('/', '_')}{ext}"
            
            # 保存附件/正文
            filepath = os.path.join(mail_dir, filename)
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    with open(filepath, 'wb') as f:
                        f.write(payload)
                    
                    if part.get_content_maintype() != 'text':
                        attachment_count += 1
                        email_info["attachments"].append({
                            "filename": filename,
                            "content_type": part.get_content_type(),
                            "size": len(payload)
                        })
                        logger.info(f"保存附件: {filename} ({len(payload)}字节)")
            except Exception as e:
                logger.error(f"保存附件 {filename} 失败: {str(e)}")
        
        # 更新邮件信息
        with open(info_path, 'w') as f:
            json.dump(email_info, f, indent=2)
        
        logger.info(f"邮件处理完成，共找到 {attachment_count} 个附件")
        
    except Exception as e:
        logger.error(f"处理邮件数据失败: {str(e)}")
# 处理非SSL连接
def handle_plain_client(client_socket: socket.socket, client_address: Tuple[str, int], traffic_dir: str) -> None:
    """处理非SSL连接，尝试捕获任何数据"""
    logger = logging.getLogger(f"plain_client_{client_address[0]}_{client_address[1]}")
    logger.info(f"New plain connection established")
    
    # 生成会话ID
    session_id = generate_session_id(client_address, datetime.datetime.now())
    
    try:
        # 尝试接收任何初始数据
        client_socket.settimeout(10)  # 短超时以快速捕获数据
        try:
            data = client_socket.recv(8192)
            if data:
                logger.info(f"Received initial data: {len(data)} bytes")
                log_raw_traffic(traffic_dir, session_id, client_address, data, "client_to_server")
                
                # 发送SMTP欢迎消息，看看客户端是否会响应
                greeting = "220 SMTP Service Ready\r\n"
                client_socket.send(greeting.encode())
                log_raw_traffic(traffic_dir, session_id, client_address, greeting.encode(), "server_to_client")
                
                # 尝试再次接收数据
                client_socket.settimeout(10)
                try:
                    response_data = client_socket.recv(8192)
                    if response_data:
                        logger.info(f"Received response data: {len(response_data)} bytes")
                        log_raw_traffic(traffic_dir, session_id, client_address, response_data, "client_to_server")
                except Exception:
                    pass
        except Exception:
            # 没有初始数据，发送欢迎消息
            greeting = "220 SMTP Service Ready\r\n"
            client_socket.send(greeting.encode())
            log_raw_traffic(traffic_dir, session_id, client_address, greeting.encode(), "server_to_client")
            
            # 尝试接收响应
            try:
                client_socket.settimeout(10)
                data = client_socket.recv(8192)
                if data:
                    logger.info(f"Received data after greeting: {len(data)} bytes")
                    log_raw_traffic(traffic_dir, session_id, client_address, data, "client_to_server")
            except Exception:
                pass
    except Exception as e:
        logger.error(f"Error handling plain client: {str(e)}")
    finally:
        client_socket.close()
        logger.info("Plain connection closed")

# 主SMTPS服务器
# [前面的导入和工具函数保持不变...]

class SMTPSServer:
    # [前面的__init__和_init_ssl_context保持不变...]
    def __init__(self, host: str = '0.0.0.0', ports = [465,587],
                 cert_file: str = 'cert.pem', key_file: str = 'key.pem',
                 log_dir: str = 'logs', traffic_dir: str = 'traffic',
                 debug: bool = False, capture_all: bool = True):
        """使用配置参数初始化SMTPS服务器"""
        self.host = host
        self.ports = ports if isinstance(ports, list) else [ports]
        self.sockets = []
        self.cert_file = cert_file
        self.key_file = key_file
        self.log_dir = log_dir
        self.traffic_dir = traffic_dir
        self.debug = debug
        self.capture_all = capture_all  # 是否捕获所有连接尝试
        self.logger = logging.getLogger("smtps_server")
        self.ssl_context = None  # 存储SSL上下文以便在不同方法间共享
    
    def _init_ssl_context(self):
        """初始化SSL上下文"""
        try:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.load_cert_chain(
                certfile=self.cert_file, 
                keyfile=self.key_file
            )
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
            self.ssl_context.options |= ssl.OP_NO_SSLv2
            self.ssl_context.options |= ssl.OP_NO_SSLv3
            try:
                self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
                self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
            except AttributeError:
                self.logger.info("Using legacy SSL protocol configuration")
        except Exception as e:
            self.logger.error(f"SSL context initialization failed: {str(e)}")
            raise       
       
    def start(self) -> None:
        """Start the SMTPS server"""
        # Check if certificate and key files exist
        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            self.logger.error("Certificate or key file not found!")
            raise FileNotFoundError("Certificate or key file not found")

        self._init_ssl_context()

        for port in self.ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.host, port))
                sock.listen(5)
                self.sockets.append((sock, port))
                self.logger.info(f"Successfully listening on port {port}")
            except OSError as e:
                self.logger.error(f"Failed to listen on port {port}: {str(e)}")
                continue
        
        if not self.sockets:
            raise RuntimeError("No available listening ports")
        
        try:
            while True:
                readable, _, _ = select.select([s[0] for s in self.sockets], [], [], 1)  # 添加1秒超时
                for sock, port in [(s, p) for s, p in self.sockets if s in readable]:
                    try:
                        client, addr = sock.accept()
                        self.logger.info(f"Connection from {addr} on port {port}")
                        threading.Thread(
                            target=self.handle_connection,
                            args=(client, addr, port),
                            daemon=True
                        ).start()
                    except Exception as e:
                        self.logger.error(f"Error accepting connection: {str(e)}")
        except KeyboardInterrupt:
            self.logger.info("Received shutdown signal")
        except Exception as e:
            self.logger.error(f"Server error: {str(e)}")
        finally:
            self.stop()

    def handle_connection(self, client_socket: socket.socket, client_address: Tuple[str, int], port: int):
        """Handle new connection and capture both encrypted and decrypted traffic"""
        session_id = generate_session_id(client_address, datetime.datetime.now())
        logger = self.logger.getChild(f"conn_{session_id}")
        logger.info(f"New connection from {client_address} on port {port}")
        
        initial_data = None
        handshake_data = bytearray()
        is_ssl = False

        try:
            # Try to capture any initial data before SSL handshake
            if self.capture_all:
                try:
                    client_socket.settimeout(1.0)
                    initial_data = client_socket.recv(8192, socket.MSG_PEEK)
                    if initial_data:
                        logger.debug(f"Captured {len(initial_data)} bytes pre-SSL handshake")
                        log_raw_tls_traffic(self.traffic_dir, session_id, client_address, 
                                         initial_data, "pre_ssl_client_to_server")
                except (socket.timeout, BlockingIOError):
                    logger.debug("No pre-SSL data captured")
                except Exception as e:
                    logger.debug(f"Error capturing pre-SSL data: {str(e)}")
                finally:
                    client_socket.settimeout(None)

            # Try SSL handshake
            try:
                ssl_socket = self.ssl_context.wrap_socket(
                    client_socket,
                    server_side=True,
                    do_handshake_on_connect=False
                )
                
                # Manual handshake to capture handshake data
                try:
                    ssl_socket.do_handshake()
                    is_ssl = True
                    logger.info("SSL handshake successful")
                    
                    # Get TLS info
                    cipher = ssl_socket.cipher()
                    tls_info = {
                        "cipher": cipher[0],
                        "version": ssl_socket.version(),
                        "bits": cipher[2] if len(cipher) > 2 else "Unknown"
                    }
                    logger.info(f"TLS connection established: {tls_info}")
                    
                    # Handle encrypted connection
                    handle_client(ssl_socket, client_address, self.traffic_dir)
                    return
                
                except ssl.SSLWantReadError:
                    # Capture handshake data
                    logger.debug("SSL handshake in progress, capturing handshake data")
                    while True:
                        try:
                            data = ssl_socket.recv(8192)
                            if not data:
                                break
                            handshake_data.extend(data)
                            ssl_socket.do_handshake()
                            is_ssl = True
                            break
                        except ssl.SSLWantReadError:
                            continue
                        except Exception as e:
                            logger.error(f"Error during handshake: {str(e)}")
                            raise
                    
                    if is_ssl:
                        cipher = ssl_socket.cipher()
                        tls_info = {
                            "cipher": cipher[0],
                            "version": ssl_socket.version(),
                            "bits": cipher[2] if len(cipher) > 2 else "Unknown"
                        }
                        logger.info(f"TLS connection established after retry: {tls_info}")
                        handle_client(ssl_socket, client_address, self.traffic_dir)
                        return
                    
            except ssl.SSLError as ssl_err:
                logger.error(f"SSL handshake failed: {str(ssl_err)}")
                if handshake_data:
                    logger.debug(f"Captured {len(handshake_data)} bytes of handshake data")
                    log_raw_tls_traffic(self.traffic_dir, session_id, client_address,
                                     handshake_data, "ssl_handshake_client_to_server")
            
            # If SSL failed, handle as plain connection
            if self.capture_all:
                logger.info("Falling back to plain connection handling")
                all_data = bytearray()
                if initial_data:
                    all_data.extend(initial_data)
                if handshake_data:
                    all_data.extend(handshake_data)
                
                if all_data:
                    logger.debug(f"Captured {len(all_data)} bytes of raw data")
                    log_raw_traffic(self.traffic_dir, session_id, client_address,
                                 bytes(all_data), "client_to_server")
                
                # Rewind the socket if we have initial data
                if initial_data:
                    client_socket = self._prepend_to_socket(client_socket, initial_data)
                
                handle_plain_client(client_socket, client_address, self.traffic_dir)
            else:
                client_socket.close()

        except Exception as e:
            logger.error(f"Error handling connection: {str(e)}")
            log_connection_attempt(self.traffic_dir, client_address, str(e))
            try:
                client_socket.close()
            except:
                pass


    def _prepend_to_socket(self, sock: socket.socket, data: bytes) -> socket.socket:
        """创建一个新的socket，将数据预先放入缓冲区"""
        class PreloadedSocket:
            def __init__(self, sock, data):
                self.sock = sock
                self.buffer = data
            def recv(self, size):
                if self.buffer:
                    ret = self.buffer[:size]
                    self.buffer = self.buffer[size:]
                    if len(ret) > 0:
                        return ret
                return self.sock.recv(size)
            def __getattr__(self, name):
                return getattr(self.sock, name)
        
        return PreloadedSocket(sock, data)

# Main function
def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='SMTPS Honeypot with Consolidated Logging')
    parser.add_argument('--host', default='0.0.0.0', help='Listening host (default: 0.0.0.0)')
    parser.add_argument('--ports', nargs='+', type=int, default=[465, 587],help='监听端口列表 (default: 465 587)')
    parser.add_argument('--cert', default='cert.pem', help='SSL certificate file (default: cert.pem)')
    parser.add_argument('--key', default='key.pem', help='SSL key file (default: key.pem)')
    parser.add_argument('--log-dir', default='logs', help='Log directory (default: logs)')
    parser.add_argument('--traffic-dir', default='traffic', help='Traffic storage directory (default: traffic)')
    parser.add_argument('--generate-cert', action='store_true', help='Generate self-signed certificate')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--capture-all', action='store_true', help='Capture all connection attempts, even failed ones')
    parser.add_argument('--retry', type=int, default=3, help='Number of retries if port is in use (default: 3)')
    parser.add_argument('--retry-delay', type=int, default=5, help='Seconds to wait between retries (default: 5)')
    args = parser.parse_args()
    
    if isinstance(args.ports, int):
        args.ports = [args.ports]
    # Setup logging
    setup_logging(args.log_dir, args.debug)
    
    # Create and start server
    server = None
    last_error = None
    for attempt in range(args.retry):
        try:
            logging.info(f"Starting server (attempt {attempt}/{args.retry})...")
            server = SMTPSServer(
                host=args.host,
                ports=args.ports,
                cert_file=args.cert,
                key_file=args.key,
                log_dir=args.log_dir,
                traffic_dir=args.traffic_dir,
                debug=args.debug,
                capture_all=args.capture_all
            )
            server.start()
            break
        except OSError as e:
            last_error = e
            if "Address already in use" in str(e):
                logging.warning(f"Port {args.ports} in use, retrying in {args.retry_delay} seconds...")
                if server and hasattr(server, 'server_socket'):
                    server.server_socket.close()
                time.sleep(args.retry_delay)
            else:
                logging.error(f"Failed to start server: {str(e)}")
                break
        except KeyboardInterrupt:
            logging.info("Server shutdown requested by user")
            break
        except Exception as e:
            last_error = e
            logging.error(f"Unexpected error: {str(e)}")
            break

    if server:
        server.stop()

if __name__ == "__main__":
    main()