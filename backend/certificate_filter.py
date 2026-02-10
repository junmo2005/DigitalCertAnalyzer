#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TLS Certificate过滤器 - 增强版
从pcap流量中提取TLS握手中的Certificate消息，并保存链信息
结合了两个版本的优点：稳定性 + 增强功能
"""

import struct
import dpkt
import socket
import json
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
import binascii
import hashlib
import os

class TLSCertificateFilter:
    """TLS证书过滤器类 - 增强版"""

    def __init__(self):
        self.certificates = []
        self.certificate_hashes = defaultdict(int)  # 证书哈希 -> 出现次数
        self.certificate_details = {}  # 证书哈希 -> 证书详细信息
        self.stats = {
            'total_packets': 0,
            'tls_packets': 0,
            'certificate_messages': 0,
            'unique_certificates': 0,
            'total_certificates': 0,
            'fragmented_records': 0,  # 新增：分片记录数
            'truncated_certs': 0,    # 新增：截断证书数
            'invalid_certs': 0,      # 新增：无效证书数
            'sessions_processed': 0  # 新增：处理的会话数
        }
        self.chains = []  # 保存证书链信息
        self.known_ports = {443, 8443, 9443, 10443}  # 扩展的常见HTTPS端口
        self.tls_versions = {
            0x0301: 'TLS 1.0',
            0x0302: 'TLS 1.1', 
            0x0303: 'TLS 1.2',
            0x0304: 'TLS 1.3',
            0x7f12: 'TLS 1.3 Draft',
            0x7f13: 'TLS 1.3 Draft'
        }
        self.debug = True  # 调试模式开关

    def parse_pcap_and_extract_certificates(self, pcap_file: str) -> List[Dict]:
        """
        入口函数：解析pcap并输出所有Certificate消息

        Args:
            pcap_file: pcap文件路径

        Returns:
            证书消息列表
        """
        print(f"\n=== 开始详细解析PCAP文件 ===")
        print(f"文件路径: {pcap_file}")
        
        # 检查文件大小
        try:
            file_size = os.path.getsize(pcap_file) / 1024 / 1024
            print(f"文件大小: {file_size:.2f} MB")
        except OSError:
            print("文件大小: 未知")

        try:
            with open(pcap_file, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                sessions = self._tcp_reassemble_sessions(pcap)
            
                print(f"发现 {len(sessions)} 个TCP会话")
            
                for i, (session_key, session_data) in enumerate(sessions.items(), 1):
                    src_ip, src_port, dst_ip, dst_port = session_key
                    
                    # 增强的会话信息输出
                    if self.debug:
                        print(f"\n会话 #{i}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                        print(f"数据长度: {len(session_data['data'])} 字节")
                
                    # 扩展的端口检测逻辑
                    if (src_port in self.known_ports or dst_port in self.known_ports or 
                        (src_port > 1024 and dst_port > 1024)):  # 宽松条件
                        if self.debug:
                            print("检测到可能的TLS端口，开始解析...")
                        self._parse_tls_stream(session_data['data'])
                        self.stats['sessions_processed'] += 1
                    else:
                        if self.debug:
                            print(f"非标准端口({src_port}/{dst_port})，跳过...")
                    
            print("\n=== 解析完成 ===")
            
            # 更新唯一证书数量
            self.stats['unique_certificates'] = len(self.certificate_hashes)
            
            self._output_certificate_statistics()
            return self.certificates
        
        except Exception as e:
            print(f"\n!!! 解析过程中出错: {str(e)}")
            import traceback
            traceback.print_exc()
            return []

    def _tcp_reassemble_sessions(self, pcap) -> Dict:
        """
        TCP会话重组 - 基于第一个版本的稳定实现

        Args:
            pcap: pcap读取器对象

        Returns:
            重组后的会话字典
        """
        sessions = defaultdict(lambda: {'data': b'', 'packets': []})

        for timestamp, buf in pcap:
            self.stats['total_packets'] += 1

            try:
                # 解析以太网帧
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                ip = eth.data
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue

                tcp = ip.data

                # 创建会话键
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                session_key = (src_ip, tcp.sport, dst_ip, tcp.dport)

                # 添加到会话数据
                sessions[session_key]['data'] += tcp.data
                sessions[session_key]['packets'].append({
                    'timestamp': timestamp,
                    'seq': tcp.seq,
                    'data_len': len(tcp.data)
                })

            except (dpkt.UnpackError, dpkt.NeedData):
                continue

        return sessions

    def _parse_tls_stream(self, data_bytes: bytes) -> None:
        """
        解析一个TCP数据流中所有TLS记录 - 增强版

        Args:
            data_bytes: 原始的TCP数据流（字节串格式）。
        """
        if self.debug:
            print(f"分析TLS流 (长度: {len(data_bytes)} 字节)")
            
        offset = 0
        while offset + 5 <= len(data_bytes):
            try:
                # 调试输出原始数据头
                if self.debug:
                    header = data_bytes[offset:offset+5]
                    print(f"偏移 {offset}: 头数据 {binascii.hexlify(header).decode('ascii')}")

                # 解析TLS记录头
                record_type = struct.unpack('!B', data_bytes[offset:offset + 1])[0]
                record_version = struct.unpack('!H', data_bytes[offset + 1:offset + 3])[0]
                record_length = struct.unpack('!H', data_bytes[offset + 3:offset + 5])[0]

                if self.debug:
                    print(f"记录类型: {record_type}, 版本: 0x{record_version:04x}, 长度: {record_length}")

                # 检查记录长度是否有效
                if record_length > len(data_bytes) - (offset + 5):
                    if self.debug:
                        print(f"! 记录长度异常: 声明长度 {record_length} > 剩余数据 {len(data_bytes)-(offset+5)}")
                    
                    # 尝试处理分片记录
                    if self._handle_fragmented_record(data_bytes[offset:], record_type):
                        break
                    else:
                        break

                # 计算TLS记录载荷
                payload_start = offset + 5
                payload_end = payload_start + record_length
                payload = data_bytes[payload_start:payload_end]

                # 检查记录类型
                if record_type == 22:  # TLS握手
                    if self.debug:
                        print("发现TLS握手记录")
                    self.stats['tls_packets'] += 1
                    self._parse_handshake_messages(payload, record_version)
                elif record_type == 0x17:  # TLS应用数据
                    if self.debug:
                        print("发现TLS应用数据记录")
                elif record_type == 0x14:  # TLS ChangeCipherSpec
                    if self.debug:
                        print("发现TLS ChangeCipherSpec记录")
                else:
                    if self.debug:
                        print(f"未知记录类型: {record_type}")

                offset += 5 + record_length

            except (struct.error, IndexError) as e:
                if self.debug:
                    print(f"解析记录时出错: {str(e)}")
                break

    def _parse_handshake_messages(self, payload: bytes, tls_version: int) -> None:
        """
        解析Handshake消息流，寻找Certificate类型（类型值11）

        Args:
            payload: 握手消息载荷
            tls_version: TLS版本
        """
        if self.debug:
            print(f"解析握手消息 (版本: 0x{tls_version:04x}, 长度: {len(payload)} 字节)")

        hs_offset = 0

        while hs_offset + 4 <= len(payload):
            try:
                # 解析握手消息头
                hs_type = struct.unpack('!B', payload[hs_offset:hs_offset+1])[0]
                hs_length_bytes = payload[hs_offset+1:hs_offset+4]
                hs_length = struct.unpack('!I', b'\x00' + hs_length_bytes)[0]  # 24位长度

                if hs_offset + 4 + hs_length > len(payload):
                    break

                hs_body = payload[hs_offset+4:hs_offset+4+hs_length]

                # 调试输出握手消息头
                if self.debug and hs_offset == 0:
                    preview = binascii.hexlify(payload[:min(10, len(payload))]).decode('ascii')
                    print(f"握手消息头预览: {preview}...")

                # 如果是Certificate消息（类型11）
                if hs_type == 11:
                    print(f"发现Certificate消息，TLS版本: 0x{tls_version:04x}")
                    cert_msg = self._parse_certificate_message(hs_body, tls_version)
                    if cert_msg:
                        self.certificates.append(cert_msg)
                        self.stats['certificate_messages'] += 1
                        self._output_certificate_info(cert_msg)
                        # 保存链信息
                        self.chains.append({
                            'tls_version': cert_msg['tls_version_str'],
                            'certificates': [cert['hash'] for cert in cert_msg['certificates']]
                        })

                hs_offset += 4 + hs_length

            except (struct.error, IndexError) as e:
                if self.debug:
                    print(f"解析握手消息时出错: {str(e)}")
                break

    def _parse_certificate_message(self, body: bytes, tls_version: int) -> Optional[Dict]:
        """
        解析CertificateHandshake消息体，区分TLS1.2/TLS1.3格式

        Args:
            body: 证书消息体
            tls_version: TLS版本

        Returns:
            解析后的证书消息字典
        """
        try:
            cursor = 0
            certificate_list = []

            # TLS版本判断
            if tls_version <= 0x0303:  # TLS1.2及以前
                # 证书链总长度（3字节）
                if cursor + 3 > len(body):
                    return None
                list_len = struct.unpack('!I', b'\x00' + body[cursor:cursor+3])[0]
                cursor += 3
            else:  # TLS1.3
                # CertificateRequestContext长度（1字节）及其内容
                if cursor + 1 > len(body):
                    return None
                context_len = struct.unpack('!B', body[cursor:cursor+1])[0]
                cursor += 1 + context_len

                # 证书链总长度（3字节）
                if cursor + 3 > len(body):
                    return None
                list_len = struct.unpack('!I', b'\x00' + body[cursor:cursor+3])[0]
                cursor += 3

            end_of_list = cursor + list_len

            # 解析证书链
            while cursor + 3 <= end_of_list and cursor + 3 <= len(body):
                # 单个证书长度（3字节）
                cert_len = struct.unpack('!I', b'\x00' + body[cursor:cursor+3])[0]
                cursor += 3

                if cursor + cert_len > len(body):
                    self.stats['truncated_certs'] += 1
                    if self.debug:
                        print(f"证书数据截断: 需要 {cert_len} 字节，但只有 {len(body)-cursor} 字节可用")
                    break

                # DER编码的证书数据
                cert_data = body[cursor:cursor+cert_len]
                cursor += cert_len

                # TLS1.3可选：证书扩展长度及内容
                if tls_version > 0x0303:
                    if cursor + 2 <= len(body):
                        ext_len = struct.unpack('!H', body[cursor:cursor+2])[0]
                        cursor += 2 + ext_len

                # 验证证书基本结构
                if not self._validate_certificate(cert_data):
                    self.stats['invalid_certs'] += 1
                    if self.debug:
                        print(f"无效证书结构，跳过 (长度: {len(cert_data)} 字节)")
                    continue

                # 计算证书哈希
                cert_hash = hashlib.sha256(cert_data).hexdigest()

                certificate_list.append({
                    "length": cert_len,
                    "data": cert_data,
                    "data_hex": binascii.hexlify(cert_data).decode('ascii'),
                    "hash": cert_hash
                })

                # 统计证书出现次数
                self.certificate_hashes[cert_hash] += 1
                self.stats['total_certificates'] += 1

                # 保存证书详细信息（首次出现时）
                if cert_hash not in self.certificate_details:
                    self.certificate_details[cert_hash] = {
                        "first_seen": True,
                        "length": cert_len,
                        "data": cert_data,
                        "data_hex": binascii.hexlify(cert_data).decode('ascii')[:64] + "..."
                    }

            return {
                "tls_version": tls_version,
                "tls_version_str": self._get_tls_version_string(tls_version),
                "certificate_count": len(certificate_list),
                "certificates": certificate_list
            }

        except (struct.error, IndexError) as e:
            print(f"解析证书消息时出错: {e}")
            return None

    def _handle_fragmented_record(self, partial_data: bytes, record_type: int) -> bool:
        """
        处理分片TLS记录 - 新增功能
        
        Args:
            partial_data: 部分数据
            record_type: 记录类型
            
        Returns:
            是否成功处理
        """
        if len(partial_data) < 5:
            return False
        
        try:
            # 尝试解析可能的分片记录头
            record_version = struct.unpack('!H', partial_data[1:3])[0]
            if record_version not in self.tls_versions:
                return False
            
            # 如果是握手记录且数据不完整，记录统计
            if record_type == 22:
                self.stats['fragmented_records'] += 1
                if self.debug:
                    print(f"检测到分片TLS记录，版本: 0x{record_version:04x}")
                return True
            
        except struct.error:
            pass
        return False

    def _validate_certificate(self, cert_data: bytes) -> bool:
        """
        基本证书结构验证 - 新增功能
        
        Args:
            cert_data: 证书数据
            
        Returns:
            是否有效
        """
        try:
            # 最小DER证书长度检查
            if len(cert_data) < 64:  # 证书至少包含头部和基本字段
                return False
            
            # 检查ASN.1 SEQUENCE标签
            if cert_data[0] != 0x30:  # SEQUENCE tag
                return False
            
            # 检查长度字段
            length_byte = cert_data[1]
            if length_byte & 0x80:  # 长格式长度
                num_bytes = length_byte & 0x7F
                if len(cert_data) < 2 + num_bytes:
                    return False
                length = int.from_bytes(cert_data[2:2+num_bytes], 'big')
                if 2 + num_bytes + length > len(cert_data):
                    return False
            else:  # 短格式长度
                if 2 + length_byte > len(cert_data):
                    return False
            
            return True
            
        except Exception:
            return False

    def _get_tls_version_string(self, version: int) -> str:
        """获取TLS版本字符串"""
        return self.tls_versions.get(version, f"Unknown (0x{version:04x})")

    def _output_certificate_info(self, cert_msg: Dict) -> None:
        """输出证书信息"""
        print("\n=== 发现Certificate握手消息 ===")
        print(f"TLS版本: {cert_msg['tls_version_str']}")
        print(f"证书数量: {cert_msg['certificate_count']}")

        for i, cert in enumerate(cert_msg['certificates']):
            print(f"  证书 #{i+1}:")
            print(f"    长度: {cert['length']} 字节")
            print(f"    哈希: {cert['hash'][:16]}...")
            print(f"    出现次数: {self.certificate_hashes[cert['hash']]}")
            hex_preview = cert['data_hex'][:64]  # 前32字节
            print(f"    数据预览: {hex_preview}...")

    def save_certificates_to_files(self, output_dir: str = "certificates") -> None:
        """
        将提取的证书保存到文件，并保存链信息 - 稳定版本

        Args:
            output_dir: 输出目录
        """
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        cert_index = 0
        for msg_idx, cert_msg in enumerate(self.certificates):
            for cert_idx, cert in enumerate(cert_msg['certificates']):
                cert_index += 1
                filename = f"{output_dir}/cert_{cert_index:03d}_msg{msg_idx+1}_cert{cert_idx+1}.der"

                with open(filename, 'wb') as f:
                    f.write(cert['data'])

                print(f"保存证书: {filename}")

        # 保存链信息
        chain_file = f"{output_dir}/certificate_chains.json"
        with open(chain_file, 'w') as f:
            json.dump(self.chains, f, indent=2)
        print(f"保存链信息: {chain_file}")

        # 保存统计信息
        stats_file = f"{output_dir}/extraction_stats.json"
        with open(stats_file, 'w') as f:
            json.dump(self.stats, f, indent=2)
        print(f"保存统计信息: {stats_file}")

        print(f"总共保存了 {cert_index} 个证书文件")

    def _output_certificate_statistics(self) -> None:
        """输出证书统计信息"""
        print(f"\n=== 证书统计详情 ===")

        if not self.certificate_hashes:
            print("未发现任何证书")
            return

        # 按出现次数排序
        sorted_certs = sorted(self.certificate_hashes.items(), key=lambda x: x[1], reverse=True)

        print(f"处理的TCP会话数: {self.stats['sessions_processed']}")
        print(f"唯一证书总数: {len(sorted_certs)}")
        print(f"证书实例总数: {sum(self.certificate_hashes.values())}")
        print(f"分片记录数: {self.stats['fragmented_records']}")
        print(f"截断证书数: {self.stats['truncated_certs']}")
        print(f"无效证书数: {self.stats['invalid_certs']}")
        
        print("\n证书出现次数详情:")

        for i, (cert_hash, count) in enumerate(sorted_certs[:10], 1):  # 只显示前10个
            cert_info = self.certificate_details[cert_hash]
            print(f"{i:2d}. 证书哈希: {cert_hash[:32]}...")
            print(f"    出现次数: {count}")
            print(f"    证书长度: {cert_info['length']} 字节")
            print(f"    数据预览: {cert_info['data_hex']}")

        if len(sorted_certs) > 10:
            print(f"\n... 还有 {len(sorted_certs) - 10} 个证书未显示")

    def get_statistics(self) -> Dict:
        """获取统计信息"""
        return self.stats.copy()

    def get_certificate_counts(self) -> Dict[str, int]:
        """获取证书出现次数统计"""
        return dict(self.certificate_hashes)

    def set_debug(self, enabled: bool) -> None:
        """设置调试模式"""
        self.debug = enabled

def main():
    """主函数，用于命令行测试"""
    import sys

    if len(sys.argv) not in [2, 3]:
        print("使用方法: python certificate_filter_enhanced.py <pcap_file> [--debug]")
        print("示例: python certificate_filter_enhanced.py sample.pcap")
        print("示例: python certificate_filter_enhanced.py sample.pcap --debug")
        sys.exit(1)

    pcap_file = sys.argv[1]
    debug_mode = len(sys.argv) == 3 and sys.argv[2] == '--debug'

    try:
        # 创建过滤器实例
        filter_instance = TLSCertificateFilter()
        filter_instance.set_debug(debug_mode)

        # 解析pcap文件
        certificates = filter_instance.parse_pcap_and_extract_certificates(pcap_file)

        # 输出统计信息
        stats = filter_instance.get_statistics()
        print(f"\n=== 最终统计 ===")
        print(f"总数据包数: {stats['total_packets']}")
        print(f"TLS握手包数: {stats['tls_packets']}")
        print(f"证书消息数: {stats['certificate_messages']}")
        print(f"证书实例总数: {stats['total_certificates']}")
        print(f"唯一证书总数: {stats['unique_certificates']}")
        print(f"处理的会话数: {stats['sessions_processed']}")

        # 显示证书去重统计
        cert_counts = filter_instance.get_certificate_counts()
        if cert_counts:
            duplicate_certs = sum(1 for count in cert_counts.values() if count > 1)
            print(f"重复出现的证书数: {duplicate_certs}")
            if len(cert_counts) > 0:
                print(f"证书重复率: {duplicate_certs/len(cert_counts)*100:.1f}%")

        # 保存证书到文件
        if certificates:
            output_dir = "certificates_enhanced"
            filter_instance.save_certificates_to_files(output_dir)
            print(f"\n所有证书已保存到 '{output_dir}' 目录")
        else:
            print("未发现任何证书消息")

    except FileNotFoundError:
        print(f"错误: 找不到文件 {pcap_file}")
    except Exception as e:
        print(f"处理过程中发生错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()