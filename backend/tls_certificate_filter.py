# tls_certificate_filter.py
import dpkt
import socket
import struct

class TLSCertificateFilter:
    def parse_pcap_and_extract_certificates(self, pcap_path):
        """从PCAP文件中提取TLS证书（增强版）"""
        certificates = []
        
        try:
            with open(pcap_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                for timestamp, buf in pcap:
                    try:
                        # 解析以太网帧
                        eth = dpkt.ethernet.Ethernet(buf)
                        
                        # 检查IP数据包
                        if not isinstance(eth.data, dpkt.ip.IP):
                            continue
                            
                        ip = eth.data
                        
                        # 检查TCP数据包
                        if not isinstance(ip.data, dpkt.tcp.TCP):
                            continue
                            
                        tcp = ip.data
                        
                        # 检查数据长度
                        if len(tcp.data) < 5:  # TLS记录头长度
                            continue
                            
                        # 检查是否为TLS握手（内容类型22）
                        if tcp.data[0] != 22:
                            continue
                            
                        # 处理TLS记录
                        data = tcp.data
                        while len(data) >= 5:
                            # 解析TLS记录头
                            content_type = data[0]
                            version_major, version_minor = data[1], data[2]
                            record_length = struct.unpack('!H', data[3:5])[0]
                            
                            # 检查记录长度是否有效
                            if len(data) < 5 + record_length:
                                break
                                
                            record_data = data[5:5+record_length]
                            
                            # 处理握手记录
                            if content_type == 22:  # 握手
                                if len(record_data) < 4:
                                    break
                                    
                                handshake_type = record_data[0]
                                handshake_length = struct.unpack('!I', b'\x00' + record_data[1:4])[0]
                                
                                # 证书消息（类型11）
                                if handshake_type == 11 and len(record_data) >= 4 + handshake_length:
                                    # 跳过握手头 (4字节)
                                    certs_data = record_data[4:4+handshake_length]
                                    
                                    # 解析证书链
                                    pos = 0
                                    while pos < len(certs_data):
                                        if pos + 3 > len(certs_data):
                                            break
                                            
                                        cert_len = struct.unpack('!I', b'\x00' + certs_data[pos:pos+3])[0]
                                        pos += 3
                                        
                                        if pos + cert_len > len(certs_data):
                                            break
                                        
                                        # 提取单个证书
                                        cert_data = certs_data[pos:pos+cert_len]
                                        certificates.append({
                                            'data': cert_data,
                                            'length': cert_len
                                        })
                                        pos += cert_len
                            
                            # 移动到下一个记录
                            data = data[5+record_length:]
                            
                    except Exception as e:
                        # 忽略解析错误的数据包
                        continue
                        
        except Exception as e:
            print(f"PCAP解析错误: {str(e)}")
            
        return certificates