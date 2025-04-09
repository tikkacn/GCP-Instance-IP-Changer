import time
import os
import sys
import json
import logging
import requests
from tcping import Ping
from google.cloud import compute_v1
from google.auth import compute_engine
from google.oauth2 import service_account
import threading


# 定义日志格式
level = logging.INFO
logging.basicConfig(
    level=level, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# 创建默认配置
def create_default_config():
    default_config = {
        "global": {
            "round_time": 600,
            "key_path": "key.json",
            "tcping_server": "",
            "proxy": "",
            "ignore_location": False
        },
        "servers": [
            {
                "project_name": "atomic-envelope-123456",
                "instance_name": "instance-1",
                "ip_name": "ip-test",
                "zone_name": "asia-east1-a",
                "port": 443
            }
        ]
    }
    with open("config.json", "w") as f:
        json.dump(default_config, f, indent=4)
    return default_config


# 读取配置文件
def load_config():
    try:
        if not os.path.exists("config.json"):
            logger.error("Config file not found, creating default config")
            config = create_default_config()
            logger.error("Please update the config.json file and restart the program")
            sys.exit(1)
        else:
            with open("config.json", "r") as f:
                config = json.load(f)
                
            # 检查是否为新格式配置，如果是旧格式则转换
            if "servers" not in config:
                # 转换旧格式为新格式
                old_config = config
                config = {
                    "global": {
                        "round_time": old_config.get("round_time", 600),
                        "key_path": old_config.get("key_path", "key.json"),
                        "tcping_server": old_config.get("tcping_server", ""),
                        "proxy": old_config.get("proxy", ""),
                        "ignore_location": old_config.get("ignore", "False") == "True"
                    },
                    "servers": [
                        {
                            "project_name": old_config.get("project_name", ""),
                            "instance_name": old_config.get("instance_name", ""),
                            "ip_name": old_config.get("ip_name", ""),
                            "zone_name": old_config.get("zone_name", ""),
                            "port": old_config.get("port", 443)
                        }
                    ]
                }
                # 保存新格式
                with open("config.json", "w") as f:
                    json.dump(config, f, indent=4)
                logger.info("Config converted to new format")
            
            # 设置全局配置
            global_config = config["global"]
            round_time = global_config.get("round_time", 600)
            key_path = global_config.get("key_path", "")
            tcping_server = global_config.get("tcping_server", "")
            proxy_url = global_config.get("proxy", "")
            ignore_loc = global_config.get("ignore_location", False)
            
            # 设置凭证
            if key_path != "":
                credentials = service_account.Credentials.from_service_account_file(key_path)
            else:
                credentials = compute_engine.Credentials()
                
            # 设置代理
            if proxy_url != "":
                os.environ["http_proxy"] = proxy_url
                os.environ["https_proxy"] = proxy_url
                
            return config, credentials
                    
    except Exception as e:
        logger.error(f"Error reading config: {str(e)}")
        sys.exit(1)


class HiddenPrints:
    def __enter__(self):
        self._original_stdout = sys.stdout
        sys.stdout = open(os.devnull, 'w')

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout.close()
        sys.stdout = self._original_stdout


class CheckGFW:
    # 本地tcping
    @staticmethod
    def local_tcping(server, port):
        ping = Ping(server, port, 1)
        try:
            with HiddenPrints():
                ping.ping(4)
        except Exception as e:
            return False
        rate = Ping._success_rate(ping)
        # 根据丢包率判断是否被墙
        if float(rate) > 0:
            return True
        return False

    # 远程tcping
    @staticmethod
    def remote_tcping(server, port, tcping_server_url):
        url = f"{tcping_server_url}"
        params = {"server": server, "port": port}
        try:
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                if response.text == "True":
                    return True
                elif response.text == "False":
                    return False
            else:
                raise Exception("Remote tcping return error")
        except Exception as e:
            raise Exception(f"Remote tcping request failed: {str(e)}")

    # 第三方tcping
    @staticmethod
    def other_tcping(server, port):
        url = f"https://ping.gd/api/ip-test/{server}:{port}"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                result = response.json()[0]['result']['telnet_alive']
                if result == True:
                    return True
                elif result == False:
                    return False
            else:
                raise Exception("Other tcping return error")
        except Exception as e:
            raise Exception(f"Other tcping request failed: {str(e)}")


# 检查脚本运行地区
def check_location():
    url = "https://api.ip.sb/geoip"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data["country_code"] == "CN":
                return True
            else:
                return False
        else:
            raise Exception("Check location return error")
    except Exception as e:
        raise Exception(f"Check location error: {str(e)}")


class GCPAPI:
    def __init__(self, server_config, credentials):
        self.project_name = server_config["project_name"]
        self.instance_name = server_config["instance_name"]
        self.ip_name = server_config["ip_name"]
        self.zone_name = server_config["zone_name"]
        self.port = server_config["port"]
        self.region_name = self.zone_name[:-2]  # 从zone获取region
        self.compute_client = compute_v1.InstancesClient(credentials=credentials)
        self.address_client = compute_v1.AddressesClient(credentials=credentials)
        
        # 创建实例专用的IP历史记录文件名
        self.ip_history_file = f"ip_history_{self.project_name}_{self.instance_name}"

    # 记录 IP 地址历史
    def record_ip(self, ip):
        if ip not in self.read_ip():
            with open(self.ip_history_file, "a") as f:
                f.write(ip + "\n")

    # 读取 IP 地址历史
    def read_ip(self):
        ip_list = []
        if not os.path.exists(self.ip_history_file):
            with open(self.ip_history_file, "w") as f:
                return []
        else:
            with open(self.ip_history_file, "r") as f:
                for line in f.readlines():
                    ip_list.append(line.strip())
        return ip_list

    # 获取实例 IP 地址
    def get_instance_ip(self):
        logger.info(f"Getting instance IP address for {self.instance_name}...")
        instance = self.compute_client.get(
            project=self.project_name, zone=self.zone_name, instance=self.instance_name)
        logger.debug(instance)
        try:
            ip = instance.network_interfaces[0].access_configs[0].nat_i_p
        except Exception as e:
            if str(e) == "list index out of range":
                ip = None
            else:
                raise Exception(f"Get instance IP failed: {str(e)}")
        return ip

    # 删除未使用的 IP 地址
    def delete_unused_ip(self):
        logger.info(f"Deleting unused IP address for {self.instance_name}...")
        for address in self.address_client.list(project=self.project_name, region=self.region_name):
            logger.debug(address)
            if address.status == "RESERVED":
                self.address_client.delete(
                    project=self.project_name, region=self.region_name, address=address.name)
                # 等待 IP 地址删除完成
                while True:
                    try:
                        self.address_client.get(
                            project=self.project_name, region=self.region_name, address=address.name)
                        logger.debug(address)
                    except:
                        break
                    else:
                        time.sleep(1)

    # 解绑实例 IP 地址
    def unbind_instance_ip(self):
        logger.info(f"Unbinding instance IP address for {self.instance_name}...")
        instance = self.compute_client.get(
            project=self.project_name, zone=self.zone_name, instance=self.instance_name)
        logger.debug(instance)
        for network_interface in instance.network_interfaces:
            for access_config in network_interface.access_configs:
                self.compute_client.delete_access_config(
                    project=self.project_name,
                    zone=self.zone_name,
                    instance=self.instance_name,
                    access_config=access_config.name,
                    network_interface=network_interface.name,
                )
        # 等待 IP 地址解绑完成
        while True:
            instance = self.compute_client.get(
                project=self.project_name, zone=self.zone_name, instance=self.instance_name)
            logger.debug(instance)
            if len(instance.network_interfaces[0].access_configs) == 0:
                break
            else:
                time.sleep(1)

    # 添加新的静态 IP 地址
    def add_static_ip(self):
        logger.info(f"Adding static IP address for {self.instance_name}...")
        ip_name = f"{self.ip_name}-{str(int(time.time()))}"
        address = self.address_client.insert(
            project=self.project_name, region=self.region_name, address_resource={"name": ip_name})
        logger.debug(address)
        # 等待 IP 地址创建完成
        while True:
            address = self.address_client.get(
                project=self.project_name, region=self.region_name, address=ip_name)
            logger.debug(address)
            if address.status == "RESERVED":
                break
            else:
                time.sleep(1)
        return address.address

    # 将新的静态 IP 地址绑定到实例
    def bind_static_ip(self, ip):
        logger.info(f"Binding static IP address to instance {self.instance_name}...")
        self.compute_client.add_access_config(
            project=self.project_name,
            zone=self.zone_name,
            instance=self.instance_name,
            network_interface="nic0",
            access_config_resource={
                "name": "External NAT", "nat_i_p": ip},
        )
        # 等待 IP 地址绑定完成
        while True:
            instance = self.compute_client.get(
                project=self.project_name, zone=self.zone_name, instance=self.instance_name)
            logger.debug(instance)
            if len(instance.network_interfaces[0].access_configs) == 1:
                break
            else:
                time.sleep(1)

    # 获取静态 IP 地址数量(防止 IP 地址配额不足)
    def get_static_ip_count(self):
        logger.info(f"Getting static IP address count for {self.instance_name}...")
        count = 0
        for address in self.address_client.list(project=self.project_name, region=self.region_name):
            logger.debug(address)
            if address.status == "RESERVED":
                count += 1
        return count

    # 更换实例 IP 地址
    def change_ip(self):
        old_ip = self.get_instance_ip()
        try_count = 0
        while try_count < 20:
            try_count += 1
            if self.get_static_ip_count() >= 8:
                logger.info(
                    f"IP address quota exceeded for {self.instance_name}, deleting unused IP address...")
                self.delete_unused_ip()
            new_ip = self.add_static_ip()
            if new_ip != old_ip and new_ip not in self.read_ip():
                self.unbind_instance_ip()
                self.bind_static_ip(new_ip)
                self.record_ip(new_ip)
                break
            else:
                logger.info(f"IP address already exists for {self.instance_name}, retrying...")
        self.delete_unused_ip()
        # 如果尝试次数超过 20 次，则休眠 1 小时
        if try_count >= 20:
            logger.info(
                f"IP address change try count exceeded for {self.instance_name}, sleeping for 1 hour...")
            time.sleep(3600)
            raise Exception("IP address change try count exceeded")
        logger.info(f"{self.instance_name} OLD IP: {old_ip} -> NEW IP: {new_ip}")
        return new_ip


# 处理单个服务器的监控任务
def monitor_server(server_config, global_config, credentials):
    try:
        # 初始化GCP API实例
        gcp = GCPAPI(server_config, credentials)
        
        # 设置检测方法
        tcping_server = global_config.get("tcping_server", "")
        if tcping_server:
            def check(ip, port):
                return CheckGFW.remote_tcping(ip, port, tcping_server)
        elif global_config.get("ignore_location", False):
            def check(ip, port):
                return CheckGFW.other_tcping(ip, port)
        else:
            def check(ip, port):
                return CheckGFW.local_tcping(ip, port)
        
        # 服务器信息
        server_info = f"{gcp.project_name}/{gcp.instance_name}"
        
        logger.info(f"Starting monitor for {server_info}")
        
        while True:
            try:
                ip = gcp.get_instance_ip()
                if not ip:
                    logger.warning(f"IP is empty for {server_info}, adding IP...")
                    try:
                        ip = gcp.change_ip()
                    except Exception as e:
                        logger.error(f"Add IP failed for {server_info}: {str(e)}")
                        time.sleep(global_config["round_time"])
                        continue
                
                if check(ip, gcp.port):
                    logger.info(f"GCP server {server_info} is ok")
                else:
                    logger.info(f"GCP server {server_info} is blocked")
                    try:
                        gcp.change_ip()
                    except Exception as e:
                        logger.error(f"Change IP failed for {server_info}: {str(e)}")
                
                time.sleep(global_config["round_time"])
                
            except Exception as e:
                logger.error(f"Error monitoring {server_info}: {str(e)}")
                time.sleep(global_config["round_time"])
                continue
    
    except Exception as e:
        logger.error(f"Failed to initialize monitor for {server_config['instance_name']}: {str(e)}")


if __name__ == "__main__":
    try:
        # 加载配置
        config, credentials = load_config()
        global_config = config["global"]
        servers = config["servers"]
        
        # 检查位置
        if not global_config.get("ignore_location", False):
            logger.info("Checking location...")
            if check_location():
                if global_config.get("proxy", "") == "":
                    logger.error("Running in China, you must set proxy_url in global config")
                    time.sleep(10)
                    sys.exit(1)
            logger.info("Location check passed")
        else:
            logger.info("Ignore location check")
        
        # 启动多个服务器的监控线程
        threads = []
        for server_config in servers:
            thread = threading.Thread(
                target=monitor_server,
                args=(server_config, global_config, credentials),
                daemon=True
            )
            threads.append(thread)
            thread.start()
            logger.info(f"Started monitoring thread for {server_config['instance_name']}")
        
        # 等待所有线程结束（实际上是无限循环除非手动终止）
        for thread in threads:
            thread.join()
            
    except Exception as e:
        logger.error(f"Main process error: {str(e)}")
        time.sleep(10)
        sys.exit(1)
