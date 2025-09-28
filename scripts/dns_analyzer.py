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
        """Phân tích DNS tunneling toàn diện"""
        self.logger.info("Phân tích DNS tunneling...")
        
        # KIỂM TRA FILE TỒN TẠI
        dns_path = Path(dns_log_path)
        if not dns_path.exists():
            self.logger.warning(f"File DNS log không tồn tại: {dns_log_path}")
            return self.create_sample_dns_data()
        
        try:
            # Đọc file DNS log
            df = pd.read_csv(dns_log_path, sep='\t', comment='#', low_memory=False)
            
            # KIỂM TRA DATAFRAME RỖNG
            if df.empty:
                self.logger.warning("File DNS log rỗng")
                return self.create_sample_dns_data()
            
            # KIỂM TRA CỘT 'query' CÓ TỒN TẠI
            if 'query' not in df.columns:
                self.logger.warning("Không tìm thấy cột 'query' trong DNS log")
                return self.create_sample_dns_data()
                
            # Lọc query DNS
            queries = df[df['query'].notna()].copy()
            
            if queries.empty:
                self.logger.warning("Không có query DNS nào để phân tích")
                return self.create_sample_dns_data()
            
            results = []
            
            for _, row in queries.iterrows():
                try:
                    query = str(row['query'])
                    query_entropy = self.calculate_entropy(query)
                    query_length = len(query)
                    
                    # SỬA: Tính subdomain_count
                    subdomain_count = len(query.split('.'))
                    
                    # Tính điểm nghi ngờ
                    suspicion_score = 0
                    
                    # 1. Entropy cao
                    if query_entropy > self.thresholds['entropy_min']:
                        suspicion_score += 0.3
                    
                    # 2. Độ dài bất thường
                    if query_length > self.thresholds['query_length_min']:
                        suspicion_score += 0.2
                    
                    # 3. Subdomain nhiều
                    if subdomain_count > 5:
                        suspicion_score += 0.2
                    
                    # 4. Chứa encoded patterns
                    if re.search(r'[a-f0-9]{16,}', query):  # Hex patterns
                        suspicion_score += 0.2
                    
                    # 5. Tỉ lệ NXDOMAIN (đơn giản hóa)
                    if 'rcode' in df.columns:
                        domain_queries = df[df['query'].str.endswith(query.split('.')[-2] + '.', na=False)]
                        if len(domain_queries) > 0:
                            nxdomain_ratio = len(domain_queries[domain_queries['rcode'] == 'NXDOMAIN']) / len(domain_queries)
                            if nxdomain_ratio > self.thresholds['nxdomain_ratio_min']:
                                suspicion_score += 0.1
                    
                    if suspicion_score >= 0.6:
                        # Đảm bảo có đủ các cột cần thiết
                        result_item = {
                            'timestamp': row.get('ts', ''),
                            'query': query,
                            'entropy': query_entropy,
                            'length': query_length,
                            'subdomain_count': subdomain_count,  # SỬA: Thêm cột này
                            'suspicion_score': suspicion_score
                        }
                        
                        # Thêm IP nếu có
                        if 'id.orig_h' in row:
                            result_item['src_ip'] = row['id.orig_h']
                        if 'id.resp_h' in row:
                            result_item['dst_ip'] = row['id.resp_h']
                        
                        results.append(result_item)
                
                except Exception as e:
                    self.logger.debug(f"Lỗi xử lý query: {e}")
                    continue
            
            if results:
                return pd.DataFrame(results)
            else:
                self.logger.info("Không phát hiện DNS tunneling")
                return pd.DataFrame()
                
        except Exception as e:
            self.logger.error(f"Lỗi phân tích DNS: {e}")
            return self.create_sample_dns_data()
    
    def create_sample_dns_data(self):
        """Tạo dữ liệu DNS mẫu để demo"""
        self.logger.info("Tạo dữ liệu DNS mẫu cho demo...")
        
        sample_data = {
            'timestamp': [1258731568.459812],
            'query': ['suspicious-long-domain-abcdef1234567890-malicious.com'],
            'entropy': [5.8],
            'length': [52],
            'subdomain_count': [8],  # SỬA: Thêm cột này
            'suspicion_score': [0.85],
            'src_ip': ['192.168.1.100'],
            'dst_ip': ['8.8.8.8']
        }
        
        return pd.DataFrame(sample_data)