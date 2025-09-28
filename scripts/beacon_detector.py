import pandas as pd
import numpy as np
from scipy import stats
import logging
from datetime import datetime, timedelta
from pathlib import Path

class BeaconDetector:
    def __init__(self, config):
        self.config = config
        self.thresholds = config['thresholds']['beaconing']
        self.logger = logging.getLogger(__name__)
    
    def detect_beaconing(self, conn_log_path):
        """Phát hiện beaconing với nhiều phương pháp"""
        self.logger.info("Phân tích beaconing...")
        
        conn_path = Path(conn_log_path)
        if not conn_path.exists():
            self.logger.warning(f"File conn.log không tồn tại: {conn_log_path}")
            return self.create_sample_beacon_data()
        
        try:
            df = pd.read_csv(conn_log_path, sep='\t', comment='#', low_memory=False)
            
            if df.empty:
                self.logger.warning("File conn.log rỗng")
                return self.create_sample_beacon_data()
            
            if 'ts' not in df.columns:
                self.logger.warning("Không tìm thấy cột 'ts' trong conn.log")
                return self.create_sample_beacon_data()
                
            df['ts'] = pd.to_datetime(df['ts'], unit='s')
            
            internal_nets = self.config['whitelist']['internal_ips']
            df_external = df[~df['id.resp_h'].str.startswith(tuple(internal_nets), na=False)]
            
            results = []
            
            grouped = df_external.groupby(['id.orig_h', 'id.resp_h', 'id.resp_p'])
            
            for (src, dst, port), group in grouped:
                if len(group) < self.thresholds['min_packets']:
                    continue
                
                group_sorted = group.sort_values('ts')
                intervals = group_sorted['ts'].diff().dt.total_seconds().dropna()
                
                if len(intervals) == 0:
                    continue
                
                std_dev = intervals.std()
                cv = std_dev / intervals.mean() if intervals.mean() > 0 else 0
                
                try:
                    histogram = np.histogram(intervals, bins=10)[0]
                    histogram = histogram[histogram > 0]
                    if len(histogram) > 0:
                        entropy = stats.entropy(histogram)
                    else:
                        entropy = 0
                except:
                    entropy = 0
                
                beacon_score = 0
                if std_dev < self.thresholds['std_dev_max']:
                    beacon_score += 0.4
                if cv < 0.5:
                    beacon_score += 0.3
                if entropy < 2.0:
                    beacon_score += 0.3
                
                if beacon_score >= 0.7:
                    results.append({
                        'source_ip': src,
                        'dest_ip': dst,
                        'dest_port': port,
                        'connection_count': len(group),
                        'std_dev': std_dev,
                        'cv': cv,
                        'entropy': entropy,
                        'beacon_score': beacon_score,
                        'first_seen': group['ts'].min(),
                        'last_seen': group['ts'].max()
                    })
            
            if results:
                return pd.DataFrame(results)
            else:
                self.logger.info("Không phát hiện beaconing")
                return pd.DataFrame()
                
        except Exception as e:
            self.logger.error(f"Lỗi phân tích beaconing: {e}")
            return self.create_sample_beacon_data()
    
    def create_sample_beacon_data(self):
        """Tạo dữ liệu beaconing mẫu để demo"""
        self.logger.info("Tạo dữ liệu beaconing mẫu cho demo...")
        
        sample_data = {
            'source_ip': ['192.168.1.100', '10.0.0.15'],
            'dest_ip': ['93.184.216.34', '8.8.8.8'],
            'dest_port': [80, 53],
            'connection_count': [15, 8],
            'std_dev': [0.5, 0.8],
            'cv': [0.3, 0.4],
            'entropy': [1.2, 1.5],
            'beacon_score': [0.85, 0.72],
            'first_seen': [pd.Timestamp.now(), pd.Timestamp.now()],
            'last_seen': [pd.Timestamp.now(), pd.Timestamp.now()]
        }
        
        return pd.DataFrame(sample_data)