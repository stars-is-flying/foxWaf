#!/usr/bin/env python3
"""
WAF 性能压力测试脚本 - 增强版
支持大体积请求和 HTTPS
"""

import requests
import time
import threading
import json
import statistics
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

class WAFPerformanceTester:
    def __init__(self, base_url, host_header, port=80, use_https=False):
        self.protocol = "https" if use_https else "http"
        self.base_url = f"{self.protocol}://{base_url}:{port}"
        self.host_header = host_header
        self.session = requests.Session()
        # 忽略 SSL 证书验证
        self.session.verify = False
        # 禁用不安全请求警告
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self.headers = {
            'Host': host_header,
            'User-Agent': 'WAF-Performance-Tester/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.results = {
            'test_time': datetime.now().isoformat(),
            'throughput_metrics': [],
            'latency_metrics': [],
            'concurrency_metrics': []
        }

    def generate_large_payload(self, size_kb=1):
        """生成指定大小的请求体"""
        # 基础数据
        base_data = {
            "username": "test_user_12345",
            "email": "test.user@example.com",
            "description": "This is a test payload for WAF performance testing. ",
            "metadata": {
                "timestamp": int(time.time()),
                "session_id": "session_abcdefghijklmnopqrstuvwxyz",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        }
        
        # 重复基础数据直到达到目标大小
        payload = base_data.copy()
        current_size = len(json.dumps(payload))
        
        # 添加填充数据
        filler_text = "x" * 100  # 100字节的填充块
        while current_size < size_kb * 1024:
            payload[f"filler_{int(time.time()*1000)}"] = filler_text
            current_size = len(json.dumps(payload))
            
        return json.dumps(payload)

    def make_normal_request(self, path="/", method="GET", payload_size_kb=1):
        """发送正常请求测量性能"""
        try:
            if method.upper() == "GET":
                # GET 请求：在 URL 参数中添加数据
                params = {"data": self.generate_large_payload(payload_size_kb)[:1000]}  # URL 参数限制
                start_time = time.time()
                response = self.session.get(
                    f"{self.base_url}{path}",
                    headers=self.headers,
                    params=params,
                    timeout=10
                )
            else:
                # POST 请求：在请求体中添加数据
                data = self.generate_large_payload(payload_size_kb)
                start_time = time.time()
                response = self.session.post(
                    f"{self.base_url}{path}",
                    headers=self.headers,
                    data={"payload": data},
                    timeout=10
                )
            
            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # 转换为毫秒
            
            return {
                'status_code': response.status_code,
                'response_time': response_time,
                'success': True,
                'content_length': len(response.content),
                'request_size': len(data) if method.upper() == "POST" else len(str(params))
            }
        except Exception as e:
            return {
                'status_code': 0,
                'response_time': 0,
                'success': False,
                'error': str(e),
                'request_size': 0
            }

    def calculate_percentile(self, data, percentile):
        """手动计算百分位数（不依赖numpy）"""
        if not data:
            return 0
        
        sorted_data = sorted(data)
        index = (len(sorted_data) - 1) * percentile / 100
        lower_index = int(index)
        upper_index = lower_index + 1
        
        if upper_index >= len(sorted_data):
            return sorted_data[lower_index]
        
        weight = index - lower_index
        return sorted_data[lower_index] * (1 - weight) + sorted_data[upper_index] * weight

    def throughput_test(self, duration=60, requests_per_second=100, payload_size_kb=1, method="GET"):
        """吞吐量测试：固定时间内的请求处理能力"""
        print(f"🚀 开始吞吐量测试: {duration}秒, {requests_per_second}请求/秒, {payload_size_kb}KB/请求, {method}方法")
        
        total_requests = 0
        successful_requests = 0
        response_times = []
        total_request_size = 0
        start_time = time.time()
        
        while time.time() - start_time < duration:
            batch_start = time.time()
            batch_success = 0
            batch_size = 0
            
            # 发送一批请求
            with ThreadPoolExecutor(max_workers=min(requests_per_second, 200)) as executor:
                futures = [
                    executor.submit(
                        self.make_normal_request, 
                        "/test", 
                        method, 
                        payload_size_kb
                    ) for _ in range(requests_per_second)
                ]
                
                for future in as_completed(futures):
                    result = future.result()
                    total_requests += 1
                    total_request_size += result.get('request_size', 0)
                    
                    if result['success']:
                        successful_requests += 1
                        batch_success += 1
                        response_times.append(result['response_time'])
                        batch_size += result.get('request_size', 0)
            
            # 控制请求速率
            batch_time = time.time() - batch_start
            if batch_time < 1.0:
                time.sleep(1.0 - batch_time)
        
        # 计算指标
        actual_duration = time.time() - start_time
        throughput = successful_requests / actual_duration
        avg_response_time = statistics.mean(response_times) if response_times else 0
        error_rate = (total_requests - successful_requests) / total_requests * 100
        bandwidth_mbps = (total_request_size * 8) / (actual_duration * 1000000)  # Mbps
        
        metrics = {
            'duration': actual_duration,
            'total_requests': total_requests,
            'successful_requests': successful_requests,
            'throughput_rps': throughput,
            'avg_response_time_ms': avg_response_time,
            'error_rate_percent': error_rate,
            'p95_response_time_ms': self.calculate_percentile(response_times, 95),
            'payload_size_kb': payload_size_kb,
            'method': method,
            'total_data_mb': total_request_size / (1024 * 1024),
            'bandwidth_mbps': bandwidth_mbps
        }
        
        self.results['throughput_metrics'].append(metrics)
        print(f"✅ 吞吐量测试完成: {throughput:.2f} RPS, 平均延迟: {avg_response_time:.2f}ms, "
              f"错误率: {error_rate:.2f}%, 带宽: {bandwidth_mbps:.2f} Mbps")
        return metrics

    def concurrency_test(self, max_concurrent_users=1000, test_duration=30, payload_size_kb=1):
        """并发用户测试"""
        print(f"👥 开始并发测试: {max_concurrent_users}并发用户, {test_duration}秒, {payload_size_kb}KB/请求")
        
        response_times = []
        success_count = 0
        total_requests = 0
        total_request_size = 0
        lock = threading.Lock()
        
        def concurrent_worker(worker_id):
            nonlocal success_count, total_requests, total_request_size
            start_time = time.time()
            while time.time() - start_time < test_duration:
                # 交替使用 GET 和 POST 方法
                method = "POST" if worker_id % 2 == 0 else "GET"
                result = self.make_normal_request("/test", method, payload_size_kb)
                with lock:
                    total_requests += 1
                    total_request_size += result.get('request_size', 0)
                    if result['success']:
                        success_count += 1
                        response_times.append(result['response_time'])
        
        # 创建并发用户
        threads = []
        for i in range(min(max_concurrent_users, 500)):  # 限制最大线程数
            thread = threading.Thread(target=concurrent_worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # 等待测试完成
        for thread in threads:
            thread.join()
        
        # 计算指标
        throughput = success_count / test_duration
        avg_response_time = statistics.mean(response_times) if response_times else 0
        error_rate = (total_requests - success_count) / total_requests * 100
        bandwidth_mbps = (total_request_size * 8) / (test_duration * 1000000)
        
        metrics = {
            'concurrent_users': max_concurrent_users,
            'duration': test_duration,
            'throughput_rps': throughput,
            'avg_response_time_ms': avg_response_time,
            'error_rate_percent': error_rate,
            'total_requests': total_requests,
            'successful_requests': success_count,
            'payload_size_kb': payload_size_kb,
            'total_data_mb': total_request_size / (1024 * 1024),
            'bandwidth_mbps': bandwidth_mbps
        }
        
        self.results['concurrency_metrics'].append(metrics)
        print(f"✅ 并发测试完成: {throughput:.2f} RPS, 平均延迟: {avg_response_time:.2f}ms, "
              f"带宽: {bandwidth_mbps:.2f} Mbps")
        return metrics

    def latency_stability_test(self, requests_count=1000, payload_size_kb=1):
        """延迟稳定性测试"""
        print(f"⏱️  开始延迟稳定性测试: {requests_count}次请求, {payload_size_kb}KB/请求")
        
        response_times = []
        success_count = 0
        request_sizes = []
        
        for i in range(requests_count):
            if i % 100 == 0:
                print(f"进度: {i}/{requests_count}")
                
            # 交替使用不同方法
            method = "POST" if i % 3 == 0 else "GET"
            result = self.make_normal_request("/test", method, payload_size_kb)
            if result['success']:
                success_count += 1
                response_times.append(result['response_time'])
                request_sizes.append(result.get('request_size', 0))
            
            # 添加小延迟避免过载
            if i % 50 == 0:
                time.sleep(0.05)
        
        # 计算统计指标
        total_data_mb = sum(request_sizes) / (1024 * 1024)
        
        metrics = {
            'requests_count': requests_count,
            'success_count': success_count,
            'min_latency_ms': min(response_times) if response_times else 0,
            'max_latency_ms': max(response_times) if response_times else 0,
            'avg_latency_ms': statistics.mean(response_times) if response_times else 0,
            'p50_latency_ms': self.calculate_percentile(response_times, 50),
            'p95_latency_ms': self.calculate_percentile(response_times, 95),
            'p99_latency_ms': self.calculate_percentile(response_times, 99),
            'payload_size_kb': payload_size_kb,
            'total_data_mb': total_data_mb
        }
        
        # 计算标准差
        if response_times:
            avg = metrics['avg_latency_ms']
            variance = sum((x - avg) ** 2 for x in response_times) / len(response_times)
            metrics['std_latency_ms'] = variance ** 0.5
        else:
            metrics['std_latency_ms'] = 0
        
        self.results['latency_metrics'].append(metrics)
        print(f"✅ 延迟稳定性测试完成: 平均{metrics['avg_latency_ms']:.2f}ms, P95: {metrics['p95_latency_ms']:.2f}ms, "
              f"总数据量: {total_data_mb:.2f} MB")
        return metrics

    def mixed_workload_test(self, duration=120):
        """混合工作负载测试"""
        print(f"🔄 开始混合工作负载测试: {duration}秒")
        
        def mixed_worker(worker_id):
            response_times = []
            success_count = 0
            
            start_time = time.time()
            while time.time() - start_time < duration:
                # 随机选择负载大小和方法
                payload_size = random.choice([1, 2, 5, 10])  # 1KB, 2KB, 5KB, 10KB
                method = random.choice(["GET", "POST"])
                
                result = self.make_normal_request("/test", method, payload_size)
                if result['success']:
                    success_count += 1
                    response_times.append(result['response_time'])
                
                # 随机延迟
                time.sleep(random.uniform(0.01, 0.1))
            
            return response_times, success_count
        
        # 创建混合负载工作线程
        workers = 50
        all_response_times = []
        total_success = 0
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(mixed_worker, i) for i in range(workers)]
            
            for future in as_completed(futures):
                times, success = future.result()
                all_response_times.extend(times)
                total_success += success
        
        throughput = total_success / duration
        avg_response_time = statistics.mean(all_response_times) if all_response_times else 0
        
        metrics = {
            'duration': duration,
            'throughput_rps': throughput,
            'avg_response_time_ms': avg_response_time,
            'total_requests': total_success,
            'p95_response_time_ms': self.calculate_percentile(all_response_times, 95),
            'test_type': 'mixed_workload'
        }
        
        self.results['throughput_metrics'].append(metrics)
        print(f"✅ 混合工作负载测试完成: {throughput:.2f} RPS, 平均延迟: {avg_response_time:.2f}ms")
        return metrics

    def run_comprehensive_test(self):
        """运行全面的性能测试套件"""
        print("🎯 开始全面的 WAF 性能测试")
        print("=" * 60)
        
        # 1. 延迟稳定性测试 - 不同负载大小
        print("\n📊 阶段1: 延迟稳定性测试")
        for size in [1, 2, 5]:
            self.latency_stability_test(requests_count=300, payload_size_kb=size)
            time.sleep(2)
        
        # 2. 吞吐量测试 - 不同负载级别和方法
        print("\n📊 阶段2: 吞吐量测试")
        throughput_configs = [
            (50, 1, "GET"), (100, 1, "GET"), 
            (50, 2, "POST"), (100, 2, "POST"),
            (30, 5, "POST"), (50, 5, "POST")
        ]
        
        for rps, size, method in throughput_configs:
            self.throughput_test(
                duration=25, 
                requests_per_second=rps, 
                payload_size_kb=size, 
                method=method
            )
            time.sleep(3)
        
        # 3. 并发测试 - 不同并发级别
        print("\n📊 阶段3: 并发测试")
        for users in [100, 200, 300]:
            self.concurrency_test(
                max_concurrent_users=users, 
                test_duration=25, 
                payload_size_kb=2
            )
            time.sleep(3)
        
        # 4. 混合工作负载测试
        print("\n📊 阶段4: 混合工作负载测试")
        self.mixed_workload_test(duration=90)
        
        # 5. 长时间稳定性测试
        print("\n📊 阶段5: 长时间稳定性测试")
        self.throughput_test(
            duration=120, 
            requests_per_second=80, 
            payload_size_kb=2, 
            method="POST"
        )
        
        self.generate_report()

    def generate_report(self):
        """生成性能测试报告"""
        print("\n" + "=" * 70)
        print("📊 WAF 性能测试报告 - 增强版")
        print("=" * 70)
        
        report = {
            'test_configuration': {
                'target_url': self.base_url,
                'host_header': self.host_header,
                'protocol': self.protocol,
                'test_time': self.results['test_time']
            },
            'performance_summary': {}
        }
        
        # 汇总吞吐量数据
        if self.results['throughput_metrics']:
            throughputs = [m['throughput_rps'] for m in self.results['throughput_metrics']]
            bandwidths = [m.get('bandwidth_mbps', 0) for m in self.results['throughput_metrics']]
            
            report['performance_summary']['max_throughput_rps'] = max(throughputs)
            report['performance_summary']['avg_throughput_rps'] = statistics.mean(throughputs)
            report['performance_summary']['max_bandwidth_mbps'] = max(bandwidths) if bandwidths else 0
        
        # 汇总延迟数据
        if self.results['latency_metrics']:
            latencies = [m['avg_latency_ms'] for m in self.results['latency_metrics']]
            p95_latencies = [m['p95_latency_ms'] for m in self.results['latency_metrics']]
            
            report['performance_summary']['avg_latency_ms'] = statistics.mean(latencies)
            report['performance_summary']['avg_p95_latency_ms'] = statistics.mean(p95_latencies)
        
        # 打印详细报告
        print(f"🏁 测试目标: {self.base_url}")
        print(f"🎯 Host头部: {self.host_header}")
        print(f"🔒 协议: {self.protocol.upper()}")
        
        if self.results['throughput_metrics']:
            print("\n📈 吞吐量测试结果:")
            for i, metric in enumerate(self.results['throughput_metrics']):
                bandwidth = metric.get('bandwidth_mbps', 0)
                payload = metric.get('payload_size_kb', 0)
                method = metric.get('method', 'GET')
                print(f"   测试{i+1}: {metric['throughput_rps']:.1f} RPS, "
                      f"延迟: {metric['avg_response_time_ms']:.1f}ms, "
                      f"错误率: {metric['error_rate_percent']:.1f}%, "
                      f"带宽: {bandwidth:.1f} Mbps, "
                      f"负载: {payload}KB, 方法: {method}")
        
        if self.results['latency_metrics']:
            print(f"\n⏱️  延迟分析 (多负载平均):")
            print(f"   平均延迟: {report['performance_summary']['avg_latency_ms']:.1f}ms")
            print(f"   平均P95延迟: {report['performance_summary']['avg_p95_latency_ms']:.1f}ms")
        
        if self.results['concurrency_metrics']:
            print(f"\n👥 并发能力:")
            for metric in self.results['concurrency_metrics']:
                print(f"   {metric['concurrent_users']}用户: {metric['throughput_rps']:.1f} RPS, "
                      f"带宽: {metric.get('bandwidth_mbps', 0):.1f} Mbps")
        
        # 保存报告到文件
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"waf_performance_report_{timestamp}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump({**self.results, **report}, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 详细报告已保存到: {filename}")
        return report

def main():
    parser = argparse.ArgumentParser(description='WAF 性能测试工具 - 增强版')
    parser.add_argument('--url', default='127.0.0.1', help='目标URL或IP地址')
    parser.add_argument('--host', default='http.kabubu.com', help='Host头部值')
    parser.add_argument('--port', type=int, default=80, help='端口号')
    parser.add_argument('--https', action='store_true', help='使用HTTPS协议')
    
    args = parser.parse_args()
    
    # 创建测试器并运行测试
    tester = WAFPerformanceTester(args.url, args.host, args.port, args.https)
    
    try:
        tester.run_comprehensive_test()
    except KeyboardInterrupt:
        print("\n⚠️  测试被用户中断")
    except Exception as e:
        print(f"❌ 测试过程中发生错误: {e}")

if __name__ == "__main__":
    import random
    main()