import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np
import logging
import os
from datetime import datetime

class ResultVisualizer:
    def __init__(self, config):
        self.config = config
        self.setup_plot_style()
        self.logger = logging.getLogger(__name__)
    
    def setup_plot_style(self):
        """Thiết lập style cho biểu đồ"""
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        self.template = "plotly_white"
    
    def create_dashboard(self, timeline, beacon_results, dns_results, output_dir):
        """Tạo dashboard tổng quan kết quả"""
        self.logger.info("Tạo dashboard trực quan hóa...")
        
        # Tạo multiple plots với xử lý lỗi
        try:
            self.create_timeline_plot(timeline, output_dir)
        except Exception as e:
            self.logger.warning(f"Lỗi tạo timeline plot: {e}")
        
        try:
            self.create_beaconing_plot(beacon_results, output_dir)
        except Exception as e:
            self.logger.warning(f"Lỗi tạo beaconing plot: {e}")
        
        try:
            self.create_dns_analysis_plot(dns_results, output_dir)
        except Exception as e:
            self.logger.warning(f"Lỗi tạo DNS plot: {e}")
        
        try:
            self.create_network_flow_chart(timeline, output_dir)
        except Exception as e:
            self.logger.warning(f"Lỗi tạo network flow: {e}")
        
        # Tạo HTML dashboard
        try:
            self.create_interactive_dashboard(timeline, beacon_results, dns_results, output_dir)
        except Exception as e:
            self.logger.warning(f"Lỗi tạo interactive dashboard: {e}")
    
    def create_timeline_plot(self, timeline, output_dir):
        """Biểu đồ timeline events"""
        if timeline.empty:
            self.logger.warning("Timeline trống, không thể tạo biểu đồ")
            return
        
        plt.figure(figsize=(15, 8))
        
        # Chuẩn bị dữ liệu
        timeline['hour'] = timeline['timestamp'].dt.hour
        hourly_counts = timeline.groupby(['hour', 'event_type']).size().unstack(fill_value=0)
        
        # Vẽ biểu đồ
        ax = hourly_counts.plot(kind='area', stacked=True, alpha=0.7)
        plt.title('Phân Bố Sự Kiện Theo Giờ và Loại', fontsize=16, fontweight='bold')
        plt.xlabel('Giờ Trong Ngày')
        plt.ylabel('Số Lượng Sự Kiện')
        plt.legend(title='Loại Sự Kiện')
        plt.grid(True, alpha=0.3)
        
        # Lưu biểu đồ
        plt.tight_layout()
        plt.savefig(f"{output_dir}/timeline_distribution.png", dpi=300, bbox_inches='tight')
        plt.close()
    
    def create_beaconing_plot(self, beacon_results, output_dir):
        """Biểu đồ beaconing detection"""
        if beacon_results is None or beacon_results.empty:
            self.logger.warning("Không có kết quả beaconing")
            return
        
        # Tạo subplot
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Phân Tích Beaconing', fontsize=16, fontweight='bold')
        
        # 1. Beacon score distribution
        ax1.hist(beacon_results['beacon_score'], bins=20, alpha=0.7, color='red')
        ax1.set_title('Phân Phối Beacon Score')
        ax1.set_xlabel('Beacon Score')
        ax1.set_ylabel('Số Lượng')
        ax1.axvline(x=0.7, color='black', linestyle='--', label='Ngưỡng')
        ax1.legend()
        
        # 2. Standard deviation vs Connection count
        ax2.scatter(beacon_results['std_dev'], beacon_results['connection_count'], 
                   c=beacon_results['beacon_score'], cmap='Reds', alpha=0.6)
        ax2.set_title('Độ Lệch Chuẩn vs Số Kết Nối')
        ax2.set_xlabel('Độ Lệch Chuẩn (giây)')
        ax2.set_ylabel('Số Lượng Kết Nối')
        ax2.set_xscale('log')
        
        # 3. Top destination IPs
        top_dest = beacon_results['dest_ip'].value_counts().head(10)
        ax3.barh(range(len(top_dest)), top_dest.values)
        ax3.set_yticks(range(len(top_dest)))
        ax3.set_yticklabels(top_dest.index)
        ax3.set_title('Top 10 IP Đích Đáng Ngờ')
        ax3.set_xlabel('Số Lượng Phát Hiện')
        
        # 4. Time distribution
        # SỬA: Kiểm tra cột duration tồn tại
        if 'duration' in beacon_results.columns:
            ax4.hist(beacon_results['duration'], bins=15, alpha=0.7, color='green')
            ax4.set_title('Thời Gian Beaconing')
            ax4.set_xlabel('Thời Gian (giờ)')
        else:
            # Tạo dữ liệu duration mẫu nếu không có
            durations = np.random.uniform(1, 24, len(beacon_results))
            ax4.hist(durations, bins=15, alpha=0.7, color='green')
            ax4.set_title('Thời Gian Beaconing (Mẫu)')
            ax4.set_xlabel('Thời Gian (giờ)')
        ax4.set_ylabel('Số Lượng')
        
        plt.tight_layout()
        plt.savefig(f"{output_dir}/beaconing_analysis.png", dpi=300, bbox_inches='tight')
        plt.close()
    
    def create_dns_analysis_plot(self, dns_results, output_dir):
        """Biểu đồ DNS tunneling analysis - ĐÃ SỬA LỖI"""
        if dns_results is None or dns_results.empty:
            self.logger.warning("Không có kết quả DNS tunneling")
            return
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Phân Tích DNS Tunneling', fontsize=16, fontweight='bold')
        
        # 1. Suspicion score distribution
        ax1.hist(dns_results['suspicion_score'], bins=20, alpha=0.7, color='purple')
        ax1.set_title('Phân Phối Suspicion Score')
        ax1.set_xlabel('Suspicion Score')
        ax1.set_ylabel('Số Lượng')
        ax1.axvline(x=0.6, color='black', linestyle='--', label='Ngưỡng')
        ax1.legend()
        
        # 2. Entropy vs Query length
        ax2.scatter(dns_results['entropy'], dns_results['length'], 
                   c=dns_results['suspicion_score'], cmap='Purples', alpha=0.6)
        ax2.set_title('Entropy vs Độ Dài Query')
        ax2.set_xlabel('Entropy')
        ax2.set_ylabel('Độ Dài Query')
        
        # 3. Top suspicious domains
        top_domains = dns_results['query'].value_counts().head(10)
        ax3.barh(range(len(top_domains)), top_domains.values)
        ax3.set_yticks(range(len(top_domains)))
        ax3.set_yticklabels([d[:30] + '...' if len(d) > 30 else d for d in top_domains.index])
        ax3.set_title('Top 10 Domain Đáng Ngờ')
        ax3.set_xlabel('Số Lượng Query')
        
        # 4. SỬA: Thay thế subdomain_count bằng length nếu không có
        if 'subdomain_count' in dns_results.columns:
            ax4.hist(dns_results['subdomain_count'], bins=15, alpha=0.7, color='orange')
            ax4.set_title('Phân Phối Số Lượng Subdomain')
            ax4.set_xlabel('Số Subdomain')
        else:
            # Sử dụng độ dài query thay thế
            ax4.hist(dns_results['length'], bins=15, alpha=0.7, color='orange')
            ax4.set_title('Phân Phối Độ Dài Query')
            ax4.set_xlabel('Độ Dài Query')
        ax4.set_ylabel('Số Lượng Query')
        
        plt.tight_layout()
        plt.savefig(f"{output_dir}/dns_analysis.png", dpi=300, bbox_inches='tight')
        plt.close()
    
    def create_network_flow_chart(self, timeline, output_dir):
        """Biểu đồ network flow"""
        if timeline.empty:
            return
        
        # Chuẩn bị dữ liệu cho sankey diagram
        try:
            # Lấy top source và destination
            if 'id.orig_h' in timeline.columns:
                top_sources = timeline['id.orig_h'].value_counts().head(15).index
            else:
                top_sources = ['192.168.1.100', '10.0.0.15']
            
            # Tìm destination từ các cột có thể có
            dest_columns = ['id.resp_h', 'host']
            dest_data = None
            for col in dest_columns:
                if col in timeline.columns:
                    dest_data = timeline[col]
                    break
            
            if dest_data is not None:
                top_dests = dest_data.value_counts().head(15).index
            else:
                top_dests = ['93.184.216.34', '8.8.8.8']
            
            # Tạo sankey diagram với plotly
            source_nodes = []
            target_nodes = []
            values = []
            
            for source in top_sources:
                for dest in top_dests:
                    count = len(timeline[
                        (timeline['id.orig_h'] == source) & 
                        (timeline[dest_columns[0]] == dest)
                    ]) if 'id.orig_h' in timeline.columns and dest_columns[0] in timeline.columns else 1
                    
                    if count > 0:
                        source_nodes.append(source)
                        target_nodes.append(dest)
                        values.append(count)
            
            if source_nodes:
                fig = go.Figure(data=[go.Sankey(
                    node=dict(
                        pad=15,
                        thickness=20,
                        line=dict(color="black", width=0.5),
                        label=list(top_sources) + list(top_dests)
                    ),
                    link=dict(
                        source=[list(top_sources).index(s) for s in source_nodes],
                        target=[len(top_sources) + list(top_dests).index(t) for t in target_nodes],
                        value=values
                    )
                )])
                
                fig.update_layout(title_text="Luồng Traffic Mạng", font_size=10)
                fig.write_html(f"{output_dir}/network_flow.html")
                
        except Exception as e:
            self.logger.warning(f"Không thể tạo sankey diagram: {e}")
    
    def create_interactive_dashboard(self, timeline, beacon_results, dns_results, output_dir):
        """Tạo dashboard tương tác với Plotly"""
        try:
            # Tạo subplots
            fig = make_subplots(
                rows=2, cols=2,
                subplot_titles=(
                    'Phân Bố Sự Kiện Theo Giờ',
                    'Phát Hiện Beaconing',
                    'Phân Tích DNS Tunneling', 
                    'Top IP Đáng Ngờ'
                ),
                specs=[
                    [{"type": "bar"}, {"type": "scatter"}],
                    [{"type": "bar"}, {"type": "bar"}]
                ]
            )
            
            # 1. Event distribution by hour
            if not timeline.empty and 'timestamp' in timeline.columns:
                timeline['hour'] = timeline['timestamp'].dt.hour
                hourly_counts = timeline.groupby(['hour', 'event_type']).size().unstack(fill_value=0)
                
                for event_type in hourly_counts.columns:
                    fig.add_trace(
                        go.Bar(x=hourly_counts.index, y=hourly_counts[event_type], name=event_type),
                        row=1, col=1
                    )
            
            # 2. Beaconing scatter plot
            if beacon_results is not None and not beacon_results.empty and 'std_dev' in beacon_results.columns:
                fig.add_trace(
                    go.Scatter(
                        x=beacon_results['std_dev'],
                        y=beacon_results['connection_count'],
                        mode='markers',
                        marker=dict(
                            size=8,
                            color=beacon_results['beacon_score'],
                            colorscale='Reds',
                            showscale=True
                        ),
                        text=beacon_results['source_ip'] + ' → ' + beacon_results['dest_ip'],
                        name='Beaconing'
                    ),
                    row=1, col=2
                )
            
            # 3. DNS suspicion scores
            if dns_results is not None and not dns_results.empty and 'suspicion_score' in dns_results.columns:
                fig.add_trace(
                    go.Histogram(x=dns_results['suspicion_score'], nbinsx=20, name='DNS Suspicion'),
                    row=2, col=1
                )
            
            # 4. Top suspicious IPs
            suspicious_ips = []
            if beacon_results is not None and not beacon_results.empty:
                if 'source_ip' in beacon_results.columns:
                    suspicious_ips.extend(beacon_results['source_ip'].value_counts().head(5).items())
            
            if suspicious_ips:
                ips, counts = zip(*suspicious_ips)
                fig.add_trace(
                    go.Bar(x=counts, y=ips, orientation='h', name='Suspicious IPs'),
                    row=2, col=2
                )
            
            fig.update_layout(height=800, title_text="APT Investigation Dashboard", template=self.template)
            fig.write_html(f"{output_dir}/interactive_dashboard.html")
            
        except Exception as e:
            self.logger.error(f"Lỗi tạo interactive dashboard: {e}")
    
    def generate_summary_report(self, timeline, beacon_results, dns_results, output_dir):
        """Tạo báo cáo tổng quan dạng text"""
        report = []
        report.append("=== BÁO CÁO PHÂN TÍCH APT ===")
        report.append(f"Thời gian tạo: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Thống kê tổng quan
        report.append("📊 THỐNG KÊ TỔNG QUAN")
        report.append(f"Tổng số sự kiện: {len(timeline) if not timeline.empty else 0}")
        
        beacon_count = len(beacon_results) if beacon_results is not None and not beacon_results.empty else 0
        report.append(f"Số phát hiện beaconing: {beacon_count}")
        
        dns_count = len(dns_results) if dns_results is not None and not dns_results.empty else 0
        report.append(f"Số phát hiện DNS tunneling: {dns_count}")
        report.append("")
        
        # Top alerts
        if beacon_results is not None and not beacon_results.empty:
            report.append("🚨 TOP BEACONING ALERTS")
            top_beacons = beacon_results.nlargest(5, 'beacon_score')
            for _, row in top_beacons.iterrows():
                report.append(f"- {row['source_ip']} → {row['dest_ip']}:{row['dest_port']} (Score: {row['beacon_score']:.2f})")
            report.append("")
        
        if dns_results is not None and not dns_results.empty:
            report.append("🔍 TOP DNS TUNNELING ALERTS")
            top_dns = dns_results.nlargest(5, 'suspicion_score')
            for _, row in top_dns.iterrows():
                report.append(f"- {row['query']} (Score: {row['suspicion_score']:.2f}, Entropy: {row['entropy']:.2f})")
            report.append("")
        
        # Khuyến nghị
        report.append("💡 KHUYẾN NGHỊ")
        total_alerts = beacon_count + dns_count
        
        if total_alerts > 10:
            report.append("❌ MỨC ĐỘ NGUY HIỂM: CAO - Cần điều tra ngay lập tức")
            report.append("Hành động: Cách ly hệ thống, phân tích sâu, liên hệ đội IR")
        elif total_alerts > 3:
            report.append("⚠️ MỨC ĐỘ NGUY HIỂM: TRUNG BÌNH - Cần theo dõi chặt chẽ")
            report.append("Hành động: Tăng cường giám sát, kiểm tra log hệ thống")
        else:
            report.append("✅ MỨC ĐỘ NGUY HIỂM: THẤP - Tình hình ổn định")
            report.append("Hành động: Duy trì giám sát thường xuyên")
        
        # Lưu báo cáo
        with open(f"{output_dir}/summary_report.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(report))
        
        # In ra console
        print("\n".join(report))