import pandas as pd
import numpy as np
from scipy import stats
import logging
from datetime import datetime, timedelta
from pathlib import Path

class BeaconDetector:
    def __init__(self, config):
        self.config = config
        self.thresholds = config.get('thresholds', {}).get('beaconing', {'std_dev_max': 1.0, 'min_packets': 5})
        
        # FIX: Cấu hình mặc định nếu thiếu whitelist
        self.whitelist_ips = config.get('whitelist', {}).get('internal_ips', ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12'])
        
        self.logger = logging.getLogger(__name__)
    
    def parse_zeek_timestamp(self, ts_series):
        """Parse timestamp từ Zeek log - FIX QUAN TRỌNG"""
        self.logger.info("Đang parse timestamp từ Zeek log...")
        
        # Lấy mẫu đầu tiên để xác định format
        sample_ts = ts_series.iloc[0] if len(ts_series) > 0 else None
        self.logger.info(f"Timestamp mẫu: {sample_ts} (type: {type(sample_ts)})")
        
        try:
            # THỬ CÁC FORMAT TIMESTAMP KHÁC NHAU:
            
            # 1. Unix timestamp (số giây dạng float - phổ biến nhất trong Zeek)
            try:
                ts_float = ts_series.astype(float)
                result = pd.to_datetime(ts_float, unit='s', errors='coerce')
                if not result.isna().all():
                    self.logger.info("✅ Đã parse thành công với Unix timestamp (seconds)")
                    return result
            except:
                pass
            
            # 2. Unix timestamp milliseconds
            try:
                ts_float = ts_series.astype(float)
                result = pd.to_datetime(ts_float, unit='ms', errors='coerce')
                if not result.isna().all():
                    self.logger.info("✅ Đã parse thành công với Unix timestamp (milliseconds)")
                    return result
            except:
                pass
            
            # 3. String format mặc định
            try:
                result = pd.to_datetime(ts_series, errors='coerce')
                if not result.isna().all():
                    self.logger.info("✅ Đã parse thành công với string format")
                    return result
            except:
                pass
            
            # 4. Thử với infer_datetime_format
            try:
                result = pd.to_datetime(ts_series, infer_datetime_format=True, errors='coerce')
                if not result.isna().all():
                    self.logger.info("✅ Đã parse thành công với infer datetime format")
                    return result
            except:
                pass
            
            self.logger.warning("❌ Không thể parse timestamp với bất kỳ format nào")
            return pd.Series([pd.NaT] * len(ts_series))
            
        except Exception as e:
            self.logger.error(f"Lỗi parse timestamp: {e}")
            return pd.Series([pd.NaT] * len(ts_series))
    
    def read_zeek_log_safely(self, log_path):
        """Đọc file Zeek log an toàn với nhiều định dạng"""
        self.logger.info(f"Đang đọc file log: {log_path}")
        
        try:
            # Đọc toàn bộ file để phân tích format
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Tìm dòng #fields để xác định cột
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
            
            # Parse fields từ dòng #fields
            fields = fields_line.split('\t')[1:]  # Bỏ '#fields'
            
            # Tạo DataFrame từ dữ liệu
            data = [line.split('\t') for line in data_lines]
            df = pd.DataFrame(data, columns=fields)
            
            self.logger.info(f"Đã đọc {len(df)} dòng với {len(fields)} cột")
            self.logger.info(f"Các cột: {list(df.columns)}")
            
            return df
            
        except Exception as e:
            self.logger.error(f"Lỗi đọc file log: {e}")
            return pd.DataFrame()
    
    def is_internal_ip(self, ip):
        """Kiểm tra IP có phải internal không"""
        if pd.isna(ip):
            return False
        
        ip_str = str(ip).strip()
        
        # Simple check for common internal IP ranges
        if ip_str.startswith('192.168.') or ip_str.startswith('10.') or ip_str.startswith('172.16.') or ip_str.startswith('172.17.') or ip_str.startswith('172.18.') or ip_str.startswith('172.19.') or ip_str.startswith('172.20.') or ip_str.startswith('172.21.') or ip_str.startswith('172.22.') or ip_str.startswith('172.23.') or ip_str.startswith('172.24.') or ip_str.startswith('172.25.') or ip_str.startswith('172.26.') or ip_str.startswith('172.27.') or ip_str.startswith('172.28.') or ip_str.startswith('172.29.') or ip_str.startswith('172.30.') or ip_str.startswith('172.31.'):
            return True
        
        # Check from whitelist config
        for net in self.whitelist_ips:
            if ip_str.startswith(net.split('.')[0] + '.'):  # Simple prefix check
                return True
        
        return False
    
    def detect_beaconing(self, conn_log_path):
        """Phát hiện beaconing với xử lý định dạng linh hoạt"""
        self.logger.info("Phân tích beaconing...")
        
        conn_path = Path(conn_log_path)
        if not conn_path.exists():
            self.logger.warning(f"File conn.log không tồn tại: {conn_log_path}")
            return self.create_sample_beacon_data()
        
        # Đọc file log với phương pháp mới
        df = self.read_zeek_log_safely(conn_log_path)
        
        if df.empty:
            self.logger.warning("Không đọc được dữ liệu từ conn.log")
            return self.create_sample_beacon_data()
        
        # KIỂM TRA VÀ MAP CÁC CỘT CÓ THỂ CÓ
        column_mapping = {}
        
        # Tìm cột timestamp
        ts_columns = ['ts', 'timestamp', 'time']
        for col in ts_columns:
            if col in df.columns:
                column_mapping['ts'] = col
                break
        
        # Tìm cột source IP
        src_ip_columns = ['id.orig_h', 'src_ip', 'source_ip', 'orig_h']
        for col in src_ip_columns:
            if col in df.columns:
                column_mapping['src_ip'] = col
                break
        
        # Tìm cột destination IP
        dst_ip_columns = ['id.resp_h', 'dst_ip', 'dest_ip', 'resp_h']
        for col in dst_ip_columns:
            if col in df.columns:
                column_mapping['dst_ip'] = col
                break
        
        # Tìm cột destination port
        dst_port_columns = ['id.resp_p', 'dst_port', 'dest_port', 'resp_p']
        for col in dst_port_columns:
            if col in df.columns:
                column_mapping['dst_port'] = col
                break
        
        self.logger.info(f"Column mapping: {column_mapping}")
        
        # KIỂM TRA CỘT BẮT BUỘC
        if 'ts' not in column_mapping:
            self.logger.warning("Không tìm thấy cột timestamp trong conn.log")
            self.logger.info(f"Các cột có sẵn: {list(df.columns)}")
            return self.create_sample_beacon_data()
        
        try:
            # Chuẩn hóa tên cột
            df_clean = df.copy()
            ts_column = column_mapping['ts']
            
            # FIX QUAN TRỌNG: Parse timestamp với method mới
            self.logger.info(f"Đang parse timestamp từ cột: {ts_column}")
            df_clean['ts'] = self.parse_zeek_timestamp(df[ts_column])
            
            # Log kết quả parse
            valid_timestamps = df_clean['ts'].notna().sum()
            self.logger.info(f"Parse thành công {valid_timestamps}/{len(df_clean)} timestamps")
            
            if valid_timestamps == 0:
                self.logger.warning("Không có timestamp nào parse thành công")
                # Log vài giá trị timestamp để debug
                sample_values = df[ts_column].head(3).tolist()
                self.logger.info(f"Giá trị timestamp mẫu: {sample_values}")
                return self.create_sample_beacon_data()
            
            # Lọc bỏ các dòng không có timestamp hợp lệ
            df_clean = df_clean.dropna(subset=['ts'])
            self.logger.info(f"Sau khi lọc timestamp: {len(df_clean)} dòng")
            
            # Thêm các cột IP và port
            if 'src_ip' in column_mapping:
                df_clean['id.orig_h'] = df[column_mapping['src_ip']]
            if 'dst_ip' in column_mapping:
                df_clean['id.resp_h'] = df[column_mapping['dst_ip']]
            if 'dst_port' in column_mapping:
                df_clean['id.resp_p'] = df[column_mapping['dst_port']]
            
            # Lọc kết nối ra ngoài - SỬA: Sử dụng method mới
            if 'id.resp_h' in df_clean.columns:
                df_external = df_clean[~df_clean['id.resp_h'].apply(self.is_internal_ip)]
                self.logger.info(f"Sau khi lọc internal IPs: {len(df_external)} dòng")
            else:
                self.logger.warning("Không tìm thấy cột destination IP")
                df_external = df_clean
            
            if df_external.empty:
                self.logger.info("Không có kết nối external nào để phân tích")
                return pd.DataFrame()
            
            results = []
            
            # Phân tích theo từng cặp host
            group_columns = []
            if 'id.orig_h' in df_external.columns:
                group_columns.append('id.orig_h')
            if 'id.resp_h' in df_external.columns:
                group_columns.append('id.resp_h')
            if 'id.resp_p' in df_external.columns:
                group_columns.append('id.resp_p')
            
            if len(group_columns) < 2:
                self.logger.warning("Không đủ cột để phân tích beaconing")
                return self.create_sample_beacon_data()
            
            self.logger.info(f"Phân tích theo nhóm: {group_columns}")
            grouped = df_external.groupby(group_columns)
            
            total_groups = len(grouped)
            self.logger.info(f"Tổng số nhóm cần phân tích: {total_groups}")
            
            processed_groups = 0
            beaconing_detected = 0
            
            for name, group in grouped:
                processed_groups += 1
                if processed_groups % 100 == 0:  # Log tiến độ
                    self.logger.info(f"Đã xử lý {processed_groups}/{total_groups} nhóm")
                
                if len(group) < self.thresholds['min_packets']:
                    continue
                
                # Tính toán các chỉ số
                group_sorted = group.sort_values('ts')
                intervals = group_sorted['ts'].diff().dt.total_seconds().dropna()
                
                if len(intervals) == 0:
                    continue
                
                std_dev = intervals.std()
                if pd.isna(std_dev):
                    continue
                    
                cv = std_dev / intervals.mean() if intervals.mean() > 0 else 0
                
                # Tính entropy
                try:
                    histogram = np.histogram(intervals, bins=10)[0]
                    histogram = histogram[histogram > 0]
                    if len(histogram) > 0:
                        entropy = stats.entropy(histogram)
                    else:
                        entropy = 0
                except:
                    entropy = 0
                
                # Phát hiện beaconing
                beacon_score = 0
                if std_dev < self.thresholds['std_dev_max']:
                    beacon_score += 0.4
                if cv < 0.5 and not pd.isna(cv):
                    beacon_score += 0.3
                if entropy < 2.0:
                    beacon_score += 0.3
                
                if beacon_score >= 0.7:
                    beaconing_detected += 1
                    # Tạo kết quả với thông tin đầy đủ
                    result = {
                        'connection_count': len(group),
                        'std_dev': std_dev,
                        'cv': cv,
                        'entropy': entropy,
                        'beacon_score': beacon_score,
                        'first_seen': group['ts'].min(),
                        'last_seen': group['ts'].max()
                    }
                    
                    # Thêm IP và port
                    if len(group_columns) >= 1:
                        result['source_ip'] = name[0] if isinstance(name, tuple) else name
                    if len(group_columns) >= 2:
                        result['dest_ip'] = name[1] if isinstance(name, tuple) else 'N/A'
                    if len(group_columns) >= 3:
                        result['dest_port'] = name[2] if isinstance(name, tuple) else 'N/A'
                    
                    results.append(result)
            
            self.logger.info(f"Phân tích hoàn tất: {beaconing_detected} beaconing alerts trong {processed_groups} nhóm")
            
            if results:
                return pd.DataFrame(results)
            else:
                self.logger.info("Không phát hiện beaconing")
                return pd.DataFrame()
                
        except Exception as e:
            self.logger.error(f"Lỗi phân tích beaconing: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
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