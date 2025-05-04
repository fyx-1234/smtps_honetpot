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
import re
import traceback
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from typing import Tuple, Optional, Dict, List, Set

# 设置日志配置
def setup_logging(log_dir: str, debug: bool = False) -> None:
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_file = os.path.join(log_dir, f"smtps_listener_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

def generate_session_id(client_address: Tuple[str, int], timestamp: datetime.datetime) -> str:
    session_data = f"{client_address[0]}:{client_address[1]}:{timestamp.isoformat()}"
    return hashlib.md5(session_data.encode()).hexdigest()[:12]

def log_tls_traffic(traffic_dir: str, session_id: str, client_address: Tuple[str, int], 
                   data: bytes, direction: str, tls_info: Dict = None) -> None:
    log_common(traffic_dir, session_id, client_address, data, direction,
              tls_info, "tls", "TLS 流量", decode=True)

def log_raw_tls_traffic(traffic_dir: str, session_id: str, client_address: Tuple[str, int], 
                       data: bytes, direction: str, tls_info: Dict = None) -> None:
    log_common(traffic_dir, session_id, client_address, data, direction,
              tls_info, "raw_tls", "原始TLS流量", decode=False)

def log_common(traffic_dir: str, session_id: str, client_address: Tuple[str, int],
              data: bytes, direction: str, tls_info: Dict,
              log_type: str, log_title: str, decode: bool) -> None:
    timestamp = datetime.datetime.now().isoformat()
    client_ip, client_port = client_address
    
    log_dir = os.path.join(traffic_dir, log_type)
    raw_dir = os.path.join(log_dir, "raw_data")
    os.makedirs(raw_dir, exist_ok=True)
    
    raw_filename = f"{session_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{direction}.bin"
    raw_filepath = os.path.join(raw_dir, raw_filename)
    with open(raw_filepath, 'wb') as f:
        f.write(data)
    
    log_entry = {
        "session_id": session_id,
        "timestamp": timestamp,
        "client_ip": client_ip,
        "client_port": client_port,
        "direction": direction,
        "data_size": len(data),
        "raw_data_path": raw_filepath,
    }

    if tls_info:
        log_entry.update({
            "tls_version": tls_info.get("version", "Unknown"),
            "cipher": tls_info.get("cipher", "Unknown"),
            "key_bits": tls_info.get("bits", "Unknown")
        })

    try:
        if decode:
            log_entry["decrypted_data"] = data.decode('utf-8', errors='replace').strip()
        else:
            log_entry["hex_data"] = binascii.hexlify(data[:64]).decode()
    except UnicodeDecodeError:
        log_entry["hex_data"] = binascii.hexlify(data[:64]).decode()

    log_file = os.path.join(log_dir, f"{log_type}_traffic.json")
    with open(log_file, 'a') as f:
        json.dump(log_entry, f, ensure_ascii=False)
        f.write("\n")
    
    logging.debug(f"记录了 {len(data)} 字节的 {direction} {log_title}")

def log_connection_attempt(traffic_dir: str, client_address: Tuple[str, int], error_message: str) -> None:
    os.makedirs(traffic_dir, exist_ok=True)
    
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "client": f"{client_address[0]}:{client_address[1]}",
        "error": error_message
    }
    
    log_file = os.path.join(traffic_dir, "connection_attempts.json")
    with open(log_file, 'a') as f:
        json.dump(log_entry, f, ensure_ascii=False)
        f.write("\n")
    
    logging.debug(f"记录来自 {client_address} 的连接尝试")

def log_raw_traffic(traffic_dir: str, session_id: str, client_address: Tuple[str, int], data: bytes, direction: str) -> None:
    log_common(traffic_dir, session_id, client_address, data, direction,
              None, "raw", "原始非TLS流量", decode=True)

def process_email_data(data: bytes, session_id: str, client_address: Tuple[str, int], 
                      traffic_dir: str, logger: logging.Logger) -> None:
    try:
        mail_dir = os.path.join(traffic_dir, "emails", session_id)
        os.makedirs(mail_dir, exist_ok=True)
        
        raw_path = os.path.join(mail_dir, "raw.eml")
        with open(raw_path, 'wb') as f:
            f.write(data)
        logger.info(f"原始邮件已保存至: {raw_path}")

        msg = BytesParser(policy=policy.default).parsebytes(data)
        meta = {
            "from": msg['from'],
            "to": msg['to'],
            "subject": msg['subject'],
            "date": msg['date'],
            "attachments": []
        }

        attachment_count = 0
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue

            content_type = part.get_content_type()
            content_disp = part.get("Content-Disposition", "")

            is_attachment = "attachment" in content_disp.lower()
            is_inline = "inline" in content_disp.lower()
            has_filename = part.get_filename() is not None

            if not (is_attachment or has_filename or is_inline):
                continue

            filename = part.get_filename()
            if filename:
                decoded_parts = decode_header(filename)
                filename = ''.join([part.decode(encoding or 'utf-8', errors='replace') if isinstance(part, bytes) else part for part, encoding in decoded_parts])
            
            if not filename:
                ext_map = {
                    'text/plain': '.txt',
                    'text/html': '.html',
                    'application/pdf': '.pdf',
                    'application/zip': '.zip',
                    'image/jpeg': '.jpg',
                    'image/png': '.png'
                }
                ext = ext_map.get(content_type, '.bin')
                filename = f"attachment_{attachment_count}{ext}"
            else:
                filename = re.sub(r'[\\/*?:"<>|]', "_", filename)
                filename = filename.replace("\r", "").replace("\n", "")

            base_name, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(os.path.join(mail_dir, filename)):
                filename = f"{base_name}_{counter}{ext}"
                counter += 1

            filepath = os.path.join(mail_dir, filename)
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    with open(filepath, 'wb') as f:
                        f.write(payload)
                    
                    file_hash = hashlib.sha256(payload).hexdigest()
                    
                    meta["attachments"].append({
                        "filename": filename,
                        "content_type": content_type,
                        "size": len(payload),
                        "sha256": file_hash,
                        "content_disposition": content_disp
                    })
                    
                    logger.info(f"捕获附件: {filename} ({len(payload)}字节)")
                    attachment_count += 1

            except Exception as e:
                logger.error(f"保存附件失败 [{filename}]: {str(e)}")
                continue

        meta_path = os.path.join(mail_dir, "metadata.json")
        with open(meta_path, 'w', encoding='utf-8') as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)
        logger.info(f"元数据已保存至: {meta_path}")

    except Exception as e:
        logger.error(f"邮件处理失败: {str(e)}")
        logger.debug(f"Traceback: {traceback.format_exc()}", exc_info=True)

def handle_client(client_socket: ssl.SSLSocket, client_address: Tuple[str, int], traffic_dir: str) -> None:
    logger = logging.getLogger(f"client_{client_address[0]}_{client_address[1]}")
    logger.info(f"New connection established")
    
    session_id = generate_session_id(client_address, datetime.datetime.now())
    email_data = bytearray()  # 新增：用于累积邮件数据
    
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
    
    try:
        greeting = "220 SMTPS Listener Ready\r\n"
        client_socket.send(greeting.encode())
        log_tls_traffic(traffic_dir, session_id, client_address, greeting.encode(), "server_to_client", tls_info)
        log_raw_tls_traffic(traffic_dir, session_id, client_address, greeting.encode(), "server_to_client", tls_info)
        
        while True:
            client_socket.settimeout(60)
            data = client_socket.recv(8192)
            if not data:
                break
                
            email_data.extend(data)  # 累积数据
            
            try:
                logger.info(f"Received: {data.decode('utf-8', errors='replace').strip()}")
            except Exception:
                logger.info(f"Received binary data of length {len(data)}")
            
            log_tls_traffic(traffic_dir, session_id, client_address, data, "client_to_server", tls_info)
            log_raw_tls_traffic(traffic_dir, session_id, client_address, data, "client_to_server", tls_info)
            
            command = data.decode('utf-8', errors='replace').split(' ')[0].upper().strip()
            
            if command == "DATA":
                response = "354 End data with <CR><LF>.<CR><LF>\r\n"
                client_socket.send(response.encode())
                log_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                log_raw_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                logger.info("Entering DATA mode")
                
                # 接收邮件数据
                while True:
                    data = client_socket.recv(8192)
                    if not data:
                        break
                    
                    email_data.extend(data)
                    log_tls_traffic(traffic_dir, session_id, client_address, data, "client_to_server", tls_info)
                    log_raw_tls_traffic(traffic_dir, session_id, client_address, data, "client_to_server", tls_info)
                    if b"\r\n.\r\n" in email_data:
                        break
                
                # 处理邮件数据
                process_email_data(bytes(email_data), session_id, client_address, traffic_dir, logger)
                response = "250 OK: Message accepted for delivery\r\n"
                client_socket.send(response.encode())
                log_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                log_raw_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                break
            elif command == "AUTH":
                if "PLAIN" in data.decode():
                    # 直接接受任意认证
                    client_socket.send(b"235 2.7.0 Authentication successful\r\n")
                    log_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                    log_raw_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                    logger.info("Accepted authentication (PLAIN)")
                elif "LOGIN" in data.decode():
                    # 处理LOGIN认证流程
                    client_socket.send(b"334 VXNlcm5hbWU6\r\n")  # Username:
                    log_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                    log_raw_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                    # 接收用户名
                    user_data = client_socket.recv(8192)
                    client_socket.send(b"334 UGFzc3dvcmQ6\r\n")  # Password:
                    # 接收密码
                    pass_data = client_socket.recv(8192)
                    client_socket.send(b"235 2.7.0 Authentication successful\r\n")
                    log_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                    log_raw_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                    logger.info("Accepted authentication (LOGIN)")    
            else:
                if command == "EHLO" or command == "HELO" or command == "HELP":
                    response = "250-Hello\r\n250-SIZE 10240000\r\n250-AUTH LOGIN PLAIN\r\n250-STARTTLS\r\n250 OK\r\n"
                elif command == "MAIL":
                    response = "250 OK\r\n"
                elif command == "RCPT":
                    response = "250 OK\r\n"
                elif command == "AUTH":   
                    response = "250 OK\r\n"
                elif command == "QUIT":
                    response = "221 Bye\r\n"
                else:
                    response = "500 Command not recognized\r\n"
                
                client_socket.send(response.encode())
                log_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                log_raw_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
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


def handle_client_after_starttls(ssl_socket: ssl.SSLSocket, client_address: Tuple[str, int], traffic_dir: str, session_id: str, initial_data: bytes = b"") -> None:
    logger = logging.getLogger(f"client_{client_address[0]}_{client_address[1]}")
    logger.info(f"TLS connection established after STARTTLS")
    
    email_data = bytearray(initial_data)
    
    tls_info = {}
    try:
        cipher = ssl_socket.cipher()
        if cipher:
            tls_info = {
                "cipher": cipher[0],
                "version": ssl_socket.version(),
                "bits": cipher[2] if len(cipher) > 2 else "Unknown"
            }
    except Exception as e:
        logger.debug(f"获取TLS信息失败: {str(e)}")
    
    try:
        if initial_data:
            log_tls_traffic(traffic_dir, session_id, client_address, initial_data, "client_to_server", tls_info)
            log_raw_tls_traffic(traffic_dir, session_id, client_address, initial_data, "client_to_server", tls_info)
        
        while True:
            ssl_socket.settimeout(60)
            data = ssl_socket.recv(8192)
            if not data:
                break
                
            email_data.extend(data)
            
            try:
                logger.info(f"Received: {data.decode('utf-8', errors='replace').strip()}")
            except Exception:
                logger.info(f"Received binary data of length {len(data)}")
            
            log_tls_traffic(traffic_dir, session_id, client_address, data, "client_to_server", tls_info)
            log_raw_tls_traffic(traffic_dir, session_id, client_address, data, "client_to_server", tls_info)
            
            command = data.decode('utf-8', errors='replace').split(' ')[0].upper().strip()
            
            if command == "DATA":
                response = "354 End data with <CR><LF>.<CR><LF>\r\n"
                ssl_socket.send(response.encode())
                log_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                log_raw_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                logger.info("Entering DATA mode")
                
                while True:
                    data = ssl_socket.recv(8192)
                    if not data:
                        break
                    email_data.extend(data)
                    log_tls_traffic(traffic_dir, session_id, client_address, data, "client_to_server", tls_info)
                    log_raw_tls_traffic(traffic_dir, session_id, client_address, data, "client_to_server", tls_info)
                    if b"\r\n.\r\n" in email_data:
                        break
                
                process_email_data(bytes(email_data), session_id, client_address, traffic_dir, logger)
                response = "250 OK: Message accepted for delivery\r\n"
                ssl_socket.send(response.encode())
                log_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                log_raw_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                break
            elif command == "AUTH":
                if "PLAIN" in data.decode():
                    # 直接接受任意认证
                    ssl_socket.send(b"235 2.7.0 Authentication successful\r\n")
                    log_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                    log_raw_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                    logger.info("Accepted authentication (PLAIN)")
                elif "LOGIN" in data.decode():
                    # 处理LOGIN认证流程
                    ssl_socket.send(b"334 VXNlcm5hbWU6\r\n")  # Username:
                    log_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                    log_raw_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                    # 接收用户名
                    user_data = ssl_socket.recv(8192)
                    ssl_socket.send(b"334 UGFzc3dvcmQ6\r\n")  # Password:
                    # 接收密码
                    pass_data = ssl_socket.recv(8192)
                    ssl_socket.send(b"235 2.7.0 Authentication successful\r\n")
                    log_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                    log_raw_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                    logger.info("Accepted authentication (LOGIN)")    
            else:
                if command == "EHLO" or command == "HELO":
                    response = "250-Hello\r\n250-SIZE 10240000\r\n250-AUTH LOGIN PLAIN\r\n250-STARTTLS\r\n250 OK\r\n"
                elif command == "MAIL":
                    response = "250 OK\r\n"
                elif command == "RCPT":
                    response = "250 OK\r\n"
                elif command == "AUTH":   
                    response = "250 OK\r\n"
                elif command == "QUIT":
                    response = "221 Bye\r\n"
                else:
                    response = "500 Command not recognized\r\n"
                
                ssl_socket.send(response.encode())
                log_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
                log_raw_tls_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client", tls_info)
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
        ssl_socket.close()
        logger.info("TLS connection closed")

def handle_starttls_connection(client_socket: socket.socket, client_address: Tuple[str, int], traffic_dir: str, ssl_context: ssl.SSLContext, capture_all: bool) -> None:
    logger = logging.getLogger(f"starttls_{client_address[0]}_{client_address[1]}")
    session_id = generate_session_id(client_address, datetime.datetime.now())
    logger.info("New STARTTLS potential connection")
    
    try:
        client_socket.send(b"220 SMTP Service Ready\r\n")
        log_raw_traffic(traffic_dir, session_id, client_address, b"220 SMTP Service Ready\r\n", "server_to_client")
        
        buffer = b""
        tls_activated = False
        
        while True:
            data = client_socket.recv(8192)
            if not data:
                break
            
            buffer += data
            log_raw_traffic(traffic_dir, session_id, client_address, data, "client_to_server")
            
            while b'\r\n' in buffer:
                line, _, buffer = buffer.partition(b'\r\n')
                command = line.decode('utf-8', errors='replace').strip().upper()
                
                if command.startswith("STARTTLS"):
                    logger.info("Received STARTTLS command")
                    client_socket.send(b"220 Ready to start TLS\r\n")
                    log_raw_traffic(traffic_dir, session_id, client_address, b"220 Ready to start TLS\r\n", "server_to_client")
                    
                    try:
                        ssl_socket = ssl_context.wrap_socket(client_socket, server_side=True)
                        logger.info("SSL handshake completed")
                        handle_client_after_starttls(ssl_socket, client_address, traffic_dir, session_id, buffer)
                        tls_activated = True
                        break
                    except Exception as e:
                        logger.error(f"SSL handshake failed: {str(e)}")
                        return
                else:
                    response = handle_smtp_command(command)
                    client_socket.send(response.encode())
                    log_raw_traffic(traffic_dir, session_id, client_address, response.encode(), "server_to_client")
                    
                if command == "QUIT":
                    break
            
            if tls_activated:
                break
            
    except Exception as e:
        logger.error(f"Error handling connection: {str(e)}")
    finally:
        if not tls_activated:
            client_socket.close()
            logger.info("Plain connection closed")

def handle_smtp_command(command: str) -> str:
    cmd = command.split()[0].upper() if command else ""
    if cmd == "EHLO" or cmd == "HELO":
        return "250-Hello\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n250 OK\r\n"
    elif cmd == "MAIL":
        return "250 OK\r\n"
    elif cmd == "RCPT":
        return "250 OK\r\n"
    elif cmd == "QUIT":
        return "221 Bye\r\n"
    else:
        return "500 Command not recognized\r\n"

class SMTPServerWithSTARTTLS:
    def __init__(self, host: str = '0.0.0.0', port: int = 25, 
                 cert_file: str = 'cert.pem', key_file: str = 'key.pem',
                 log_dir: str = 'logs', traffic_dir: str = 'traffic',
                 debug: bool = False, capture_all: bool = True):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.log_dir = log_dir
        self.traffic_dir = traffic_dir
        self.debug = debug
        self.capture_all = capture_all
        self.server_socket = None
        self.logger = logging.getLogger(f"smtp_server_{port}")
        self.ssl_context = None
        
    def start(self) -> None:
        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            self.logger.error("Certificate or key file not found")
            return
        
        try:
            # 创建自定义 SSL 上下文（替换原有 create_default_context）
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.ssl_context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
            # 允许所有密码套件
            self.ssl_context.set_ciphers('ALL:@SECLEVEL=0')  # 降低安全等级
            # 禁用现代安全限制
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
            # 允许旧协议（移除所有 OP_NO_* 标志）
            self.ssl_context.options &= ~ssl.OP_NO_SSLv2
            self.ssl_context.options &= ~ssl.OP_NO_SSLv3
            self.ssl_context.options &= ~ssl.OP_NO_TLSv1
            self.ssl_context.options &= ~ssl.OP_NO_TLSv1_1
            
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.logger.info(f"SMTP STARTTLS honeypot started on {self.host}:{self.port}")
            
            while True:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    self.logger.info(f"Incoming connection from {client_address}")
                    
                    client_thread = threading.Thread(
                        target=handle_starttls_connection,
                        args=(client_socket, client_address, self.traffic_dir, self.ssl_context, self.capture_all)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except Exception as e:
                    self.logger.error(f"Error accepting connection: {str(e)}")
                    
        except Exception as e:
            self.logger.error(f"Server error: {str(e)}")
        finally:
            if self.server_socket:
                self.server_socket.close()
                
    def stop(self) -> None:
        if self.server_socket:
            self.server_socket.close()
            self.logger.info(f"SMTP STARTTLS honeypot on port {self.port} stopped")

class SMTPSServer:
    def __init__(self, host: str = '0.0.0.0', port: int = 465, 
                 cert_file: str = 'cert.pem', key_file: str = 'key.pem',
                 log_dir: str = 'logs', traffic_dir: str = 'traffic',
                 debug: bool = False, capture_all: bool = True):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.log_dir = log_dir
        self.traffic_dir = traffic_dir
        self.debug = debug
        self.capture_all = capture_all
        self.server_socket = None
        self.logger = logging.getLogger("smtps_server")
        self.ssl_context = None
        
    def start(self) -> None:
        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            self.logger.error("Certificate or key file not found")
            return
        
        try:
            # 创建自定义 SSL 上下文（替换原有 create_default_context）
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.ssl_context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
            # 允许所有密码套件
            self.ssl_context.set_ciphers('ALL:@SECLEVEL=0')  # 降低安全等级
            # 禁用现代安全限制
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
            # 允许旧协议（移除所有 OP_NO_* 标志）
            self.ssl_context.options &= ~ssl.OP_NO_SSLv2
            self.ssl_context.options &= ~ssl.OP_NO_SSLv3
            self.ssl_context.options &= ~ssl.OP_NO_TLSv1
            self.ssl_context.options &= ~ssl.OP_NO_TLSv1_1
            
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.logger.info(f"SMTPS honeypot started on {self.host}:{self.port}")
            
            while True:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    self.logger.info(f"Incoming connection from {client_address}")
                    
                    ssl_client_socket = self.ssl_context.wrap_socket(client_socket, server_side=True)
                    
                    client_thread = threading.Thread(
                        target=handle_client,
                        args=(ssl_client_socket, client_address, self.traffic_dir)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except Exception as e:
                    self.logger.error(f"Error accepting connection: {str(e)}")
                    
        except Exception as e:
            self.logger.error(f"Server error: {str(e)}")
        finally:
            if self.server_socket:
                self.server_socket.close()
                
    def stop(self) -> None:
        if self.server_socket:
            self.server_socket.close()
            self.logger.info("SMTPS honeypot stopped")

def generate_self_signed_cert(cert_file: str, key_file: str) -> bool:
    try:
        if os.path.exists(cert_file) and os.path.exists(key_file):
            logging.info(f"Certificate files already exist")
            return True
            
        from OpenSSL import crypto
        
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        
        cert = crypto.X509()
        cert.get_subject().CN = "localhost"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        
        with open(cert_file, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            
        with open(key_file, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
            
        logging.info(f"Generated self-signed certificate")
        return True
        
    except Exception as e:
        logging.error(f"Failed to generate certificate: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='SMTP/SMTPS Honeypot')
    parser.add_argument('--host', default='0.0.0.0', help='Listening host')
    parser.add_argument('--ports', nargs='+', type=int, default=[25, 465, 587], help='Ports to listen on')
    parser.add_argument('--cert', default='cert.pem', help='SSL certificate file')
    parser.add_argument('--key', default='key.pem', help='SSL key file')
    parser.add_argument('--log-dir', default='logs', help='Log directory')
    parser.add_argument('--traffic-dir', default='traffic', help='Traffic directory')
    parser.add_argument('--generate-cert', action='store_true', help='Generate self-signed cert')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--capture-all', action='store_true', help='Capture all connections')
    
    args = parser.parse_args()
    
    setup_logging(args.log_dir, args.debug)
    
    if args.generate_cert:
        if not generate_self_signed_cert(args.cert, args.key):
            return
    
    servers = []
    for port in args.ports:
        if port == 465:
            server = SMTPSServer(
                host=args.host, port=port,
                cert_file=args.cert, key_file=args.key,
                log_dir=args.log_dir, traffic_dir=args.traffic_dir,
                debug=args.debug, capture_all=args.capture_all
            )
        else:
            server = SMTPServerWithSTARTTLS(
                host=args.host, port=port,
                cert_file=args.cert, key_file=args.key,
                log_dir=args.log_dir, traffic_dir=args.traffic_dir,
                debug=args.debug, capture_all=args.capture_all
            )
        servers.append(server)
    
    try:
        for server in servers:
            threading.Thread(target=server.start).start()
        
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down servers...")
        for server in servers:
            server.stop()

if __name__ == "__main__":
    main()