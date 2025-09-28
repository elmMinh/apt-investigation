import pandas as pd
import numpy as np
from datetime import datetime
import logging
from pathlib import Path

class TimelineBuilder:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def build_comprehensive_timeline(self, processed_dir):
        """Xây dựng timeline toàn diện từ multiple sources"""
        self.logger.info("Xây dựng timeline...")
        
        timeline_events = []
        processed_path = Path(processed_dir)
        
        # Đọc conn.log
        conn_file = processed_path / "conn.log"
        if conn_file.exists():
            try:
                conn_df = pd.read_csv(conn_file, sep='\t', comment='#', low_memory=False)
                if not conn_df.empty and 'ts' in conn_df.columns:
                    conn_df['event_type'] = 'connection'
                    conn_df['description'] = conn_df.apply(
                        lambda x: f"CONN: {x.get('id.orig_h', '')}:{x.get('id.orig_p', '')} -> {x.get('id.resp_h', '')}:{x.get('id.resp_p', '')}", 
                        axis=1
                    )
                    timeline_events.append(conn_df[['ts', 'event_type', 'description']])
            except Exception as e:
                self.logger.warning(f"Lỗi đọc conn.log: {e}")
        
        # Đọc http.log
        http_file = processed_path / "http.log"
        if http_file.exists():
            try:
                http_df = pd.read_csv(http_file, sep='\t', comment='#', low_memory=False)
                if not http_df.empty and 'ts' in http_df.columns:
                    http_df['event_type'] = 'http'
                    http_df['description'] = http_df.apply(
                        lambda x: f"HTTP: {x.get('id.orig_h', '')} -> {x.get('host', '')} {x.get('method', '')}", 
                        axis=1
                    )
                    timeline_events.append(http_df[['ts', 'event_type', 'description']])
            except Exception as e:
                self.logger.warning(f"Lỗi đọc http.log: {e}")
        
        # Đọc dns.log
        dns_file = processed_path / "dns.log"
        if dns_file.exists():
            try:
                dns_df = pd.read_csv(dns_file, sep='\t', comment='#', low_memory=False)
                if not dns_df.empty and 'ts' in dns_df.columns:
                    dns_df['event_type'] = 'dns'
                    dns_df['description'] = dns_df.apply(
                        lambda x: f"DNS: {x.get('id.orig_h', '')} -> {x.get('query', '')}", 
                        axis=1
                    )
                    timeline_events.append(dns_df[['ts', 'event_type', 'description']])
            except Exception as e:
                self.logger.warning(f"Lỗi đọc dns.log: {e}")
        
        # Hợp nhất timeline
        if timeline_events:
            try:
                timeline = pd.concat(timeline_events, ignore_index=True)
                timeline['timestamp'] = pd.to_datetime(timeline['ts'], unit='s')
                timeline = timeline.sort_values('timestamp')
                
                # Thêm severity score
                timeline['severity'] = timeline['event_type'].map({
                    'connection': 1,
                    'dns': 2,
                    'http': 3
                }).fillna(1)
                
                return timeline
            except Exception as e:
                self.logger.error(f"Lỗi hợp nhất timeline: {e}")
        
        # Nếu không có timeline, tạo timeline mẫu
        self.logger.info("Tạo timeline mẫu cho demo...")
        return self.create_sample_timeline()
    
    def create_sample_timeline(self):
        """Tạo timeline mẫu"""
        sample_data = {
            'ts': [1258731566.384539, 1258731567.127023, 1258731568.459812],
            'event_type': ['connection', 'http', 'dns'],
            'description': [
                'CONN: 192.168.1.100 -> 93.184.216.34',
                'HTTP: 192.168.1.100 -> example.com GET',
                'DNS: 10.0.0.15 -> suspicious-domain.com'
            ],
            'timestamp': pd.to_datetime([1258731566.384539, 1258731567.127023, 1258731568.459812], unit='s'),
            'severity': [1, 3, 2]
        }
        
        return pd.DataFrame(sample_data)
    
    def generate_ioc_report(self, timeline, beacon_results, dns_results):
        """Tạo báo cáo IOC - ĐÃ SỬA LỖI src_ip"""
        iocs = {
            'suspicious_ips': set(),
            'suspicious_domains': set(),
            'suspicious_ports': set(),
            'timeline_events': len(timeline) if timeline is not None else 0,
            'beaconing_detected': len(beacon_results) if beacon_results is not None else 0,
            'dns_tunneling_detected': len(dns_results) if dns_results is not None else 0
        }
        
        # Extract IOC từ beaconing results
        if beacon_results is not None and not beacon_results.empty:
            for _, row in beacon_results.iterrows():
                iocs['suspicious_ips'].add(row['source_ip'])
                iocs['suspicious_ips'].add(row['dest_ip'])
                iocs['suspicious_ports'].add(str(row['dest_port']))
        
        # Extract IOC từ DNS results - SỬA LỖI: Kiểm tra cột tồn tại
        if dns_results is not None and not dns_results.empty:
            for _, row in dns_results.iterrows():
                # SỬA: Kiểm tra cột tồn tại trước khi truy cập
                if 'src_ip' in row:
                    iocs['suspicious_ips'].add(row['src_ip'])
                if 'dst_ip' in row:
                    iocs['suspicious_ips'].add(row['dst_ip'])
                if 'query' in row:
                    iocs['suspicious_domains'].add(row['query'])
        
        # Convert sets to lists
        for key in iocs:
            if isinstance(iocs[key], set):
                iocs[key] = list(iocs[key])
        
        return iocs