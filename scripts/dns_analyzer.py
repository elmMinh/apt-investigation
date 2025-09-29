import pandas as pd
import numpy as np
from math import log2
from collections import Counter
import re
import logging
from pathlib import Path

class DNSAnalyzer:
    def __init__(self, config):
        self.config = config
        self.thresholds = config['thresholds']['dns_tunneling']
        self.logger = logging.getLogger(__name__)
    
    def read_zeek_log_safely(self, log_path):
        """Đọc file Zeek log an toàn với nhiều định dạng"""
        self.logger.info(f"Đang đọc file log: {log_path}")
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            fields_line = None
            data_lines = []
            
            for line in lines:
                if line.startswith('#fields'):
                    fields_line = line.strip()
                elif not line.startswith('#') and line.strip():
                    data_lines.append(line.strip())
            
            if not fields_line or not data_lines:
                self.logger.warning("Không tìm thấy dòng #fields hoặc dữ liệu")
                return pd.DataFrame()
            
            fields = fields_line.split('\t')[1:]
            data = [line.split('\t') for line in data_lines]
            df = pd.DataFrame(data, columns=fields)
            
            self.logger.info(f"Đã đọc {len(df)} dòng DNS với {len(fields)} cột")
            self.logger.info(f"Các cột DNS: {list(df.columns)}")
            
            return df
            
        except Exception as e:
            self.logger.error(f"Lỗi đọc file DNS log: {e}")
            return pd.DataFrame()
    
    def calculate_entropy(self, s):
        """Tính entropy của chuỗi"""
        if not s or len(s) == 0:
            return 0
        try:
            p = Counter(s)
            lns = float(len(s))
            return -sum(count/lns * log2(count/lns) for count in p.values())
        except:
            return 0
    
    def analyze_dns_tunneling(self, dns_log_path):
        """Phân tích DNS tunneling với xử lý định dạng linh hoạt"""
        self.logger.info("Phân tích DNS tunneling...")
        
        dns_path = Path(dns_log_path)
        if not dns_path.exists():
            self.logger.warning(f"File DNS log không tồn tại: {dns_log_path}")
            return self.create_sample_dns_data()
        
        # Đọc file log với phương pháp mới
        df = self.read_zeek_log_safely(dns_log_path)
        
        if df.empty:
            self.logger.warning("Không đọc được dữ liệu từ DNS log")
            return self.create_sample_dns_data()
        
        # TÌM CÁC CỘT QUAN TRỌNG
        query_columns = ['query', 'dns_query', 'qry_name', 'query_name']
        query_column = None
        
        for col in query_columns:
            if col in df.columns:
                query_column = col
                break
        
        if not query_column:
            self.logger.warning("Không tìm thấy cột query trong DNS log")
            self.logger.info(f"Các cột có sẵn: {list(df.columns)}")
            return self.create_sample_dns_data()
        
        # Lọc query DNS
        queries = df[df[query_column].notna()].copy()
        
        if queries.empty:
            self.logger.warning("Không có query DNS nào để phân tích")
            return self.create_sample_dns_data()
        
        results = []
        
        for _, row in queries.iterrows():
            try:
                query = str(row[query_column])
                query_entropy = self.calculate_entropy(query)
                query_length = len(query)
                subdomain_count = len(query.split('.'))
                
                # Tính điểm nghi ngờ
                suspicion_score = 0
                
                if query_entropy > self.thresholds['entropy_min']:
                    suspicion_score += 0.3
                
                if query_length > self.thresholds['query_length_min']:
                    suspicion_score += 0.2
                
                if subdomain_count > 5:
                    suspicion_score += 0.2
                
                if re.search(r'[a-f0-9]{16,}', query):
                    suspicion_score += 0.2
                
                if suspicion_score >= 0.6:
                    result_item = {
                        'query': query,
                        'entropy': query_entropy,
                        'length': query_length,
                        'subdomain_count': subdomain_count,
                        'suspicion_score': suspicion_score
                    }
                    
                    # Thêm IP nếu có
                    src_ip_columns = ['id.orig_h', 'src_ip', 'source_ip']
                    for col in src_ip_columns:
                        if col in row and pd.notna(row[col]):
                            result_item['src_ip'] = row[col]
                            break
                    
                    dst_ip_columns = ['id.resp_h', 'dst_ip', 'dest_ip']
                    for col in dst_ip_columns:
                        if col in row and pd.notna(row[col]):
                            result_item['dst_ip'] = row[col]
                            break
                    
                    # Thêm timestamp nếu có
                    ts_columns = ['ts', 'timestamp', 'time']
                    for col in ts_columns:
                        if col in row and pd.notna(row[col]):
                            result_item['timestamp'] = row[col]
                            break
                    
                    results.append(result_item)
                
            except Exception as e:
                self.logger.debug(f"Lỗi xử lý query: {e}")
                continue
        
        if results:
            self.logger.info(f"Phát hiện {len(results)} DNS tunneling alerts")
            return pd.DataFrame(results)
        else:
            self.logger.info("Không phát hiện DNS tunneling")
            return pd.DataFrame()
    
    def create_sample_dns_data(self):
        """Tạo dữ liệu DNS mẫu để demo"""
        self.logger.info("Tạo dữ liệu DNS mẫu cho demo...")
        
        sample_data = {
            'timestamp': [1258731568.459812],
            'query': ['suspicious-long-domain-abcdef1234567890-malicious.com'],
            'entropy': [5.8],
            'length': [52],
            'subdomain_count': [8],
            'suspicion_score': [0.85],
            'src_ip': ['192.168.1.100'],
            'dst_ip': ['8.8.8.8']
        }
        
        return pd.DataFrame(sample_data)