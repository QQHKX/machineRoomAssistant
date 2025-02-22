# 保存为computer_room_assistant.py
'''
# 系统修复（管理员运行）
python computer_room_assistant.py --repair

# 安全扫描
python computer_room_assistant.py --scan

# 实时防护
python computer_room_assistant.py --monitor
'''

import sys
import os
import re
import ctypes
import math
import time
import random
import logging
import shutil
import platform
import subprocess
from datetime import datetime

# ==================== 环境准备部分 ====================
def check_admin():
    """检查管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except AttributeError:
        return os.getuid() == 0

def elevate_privileges():
    """请求管理员权限"""
    if not check_admin():
        print("正在请求管理员权限...")
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, __file__, None, 1
        )
        sys.exit()

def check_dependencies():
    """检查必要依赖"""
    required = {
        'psutil': 'psutil',
        'winreg': 'pywin32'
    }
    
    missing = []
    for module, pkg in required.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(pkg)
    
    return missing

def install_dependencies(missing):
    """安装缺失依赖"""
    print("正在准备安装依赖...")
    mirror = "https://pypi.tuna.tsinghua.edu.cn/simple"
    
    # 更新pip
    print("\n>>> 更新pip工具")
    pip_cmd = [
        sys.executable, "-m", "pip", "install", 
        "--upgrade", "pip", "-i", mirror, "--user"
    ]
    subprocess.run(pip_cmd, check=True)
    
    # 安装缺失包
    print(f"\n>>> 正在安装缺失包: {', '.join(missing)}")
    install_cmd = [
        sys.executable, "-m", "pip", "install",
        *missing, "-i", mirror, "--user"
    ]
    result = subprocess.run(install_cmd)
    
    if result.returncode != 0:
        print("\n错误：依赖安装失败，请手动执行以下命令：")
        print(f"pip install {' '.join(missing)} -i {mirror}")
        sys.exit(1)
        
    print("\n依赖安装完成，请重新运行程序！")
    input("按回车键退出...")
    sys.exit()

# ==================== 主程序部分 ====================
class ComputerRoomAssistant:
    """机房助手核心功能"""
    
    def __init__(self):
        self._init_system_info()
        self._init_logger()
        self.quarantine_dir = os.path.expandvars(r"%ProgramData%\MalwareQuarantine")
        self.scan_intervals = (0.5, 1.5)
        
        # 恶意软件特征库
        self.malware_db = {
            "processes": {
                "jfglzs.exe": {"risk": 9, "category": "backdoor"},
                "zmserv.exe": {"risk": 8, "category": "miner"},
                "srvany.exe": {"risk": 7, "category": "dropper"},
                "studentmain.exe": {"risk": 9, "category": "spyware"},
                "gatesrv.exe": {"risk": 8, "category": "RAT"},
                "prochelper64.exe": {"risk": 9, "category": "rootkit"},
                "masterhelper.exe": {"risk": 9, "category": "botnet"}
            },
            "signatures": [
                r"C:\\Windows\\Temp\\.+\.tmp$",
                r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{4,5}"
            ]
        }
        
        self._create_quarantine()
        self._backup_registry()

    def _init_system_info(self):
        """初始化系统信息"""
        self.win_ver = sys.getwindowsversion()
        self.is_win7 = self.win_ver.major == 6 and self.win_ver.minor == 1
        self.is_64bit = '64' in platform.machine()

    def _init_logger(self):
        """初始化日志系统"""
        self.logger = logging.getLogger('ComputerRoomAssistant')
        self.logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # 文件日志
        fh = logging.FileHandler('computer_room.log', encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)

        # 控制台日志
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(formatter)

        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def _create_quarantine(self):
        """创建隔离区"""
        if not os.path.exists(self.quarantine_dir):
            try:
                os.makedirs(self.quarantine_dir, exist_ok=True)
                FILE_ATTRIBUTE_HIDDEN = 0x2
                ctypes.windll.kernel32.SetFileAttributesW(
                    self.quarantine_dir, FILE_ATTRIBUTE_HIDDEN)
                self.logger.info("创建隔离区成功")
            except Exception as e:
                self.logger.error(f"隔离区创建失败: {str(e)}")

    def _backup_registry(self):
        """备份注册表"""
        backup_file = f"regbackup_{datetime.now().strftime('%Y%m%d%H%M')}.reg"
        try:
            subprocess.run(
                f'reg export HKLM\SOFTWARE {backup_file} /y', 
                shell=True, 
                check=True
            )
            self.logger.info(f"注册表备份至: {os.path.abspath(backup_file)}")
        except Exception as e:
            self.logger.error(f"注册表备份失败: {str(e)}")

    # ========== 系统修复功能 ==========
    def system_repair(self):
        """执行系统修复"""
        self.logger.info("=== 开始系统修复 ===")
        self._enable_system_tools()
        self._clean_temp_files()
        self._reset_network()
        self._optimize_performance()
        self.logger.info("=== 系统修复完成 ===")

    def _enable_system_tools(self):
        """启用系统工具"""
        tools = {
            'CMD': [
                (winreg.HKEY_CURRENT_USER, 
                 r"Software\Policies\Microsoft\Windows\System", "DisableCMD"),
            ],
            '注册表编辑器': [
                (winreg.HKEY_CURRENT_USER,
                 r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                 "DisableRegistryTools"),
            ]
        }
        
        for tool, entries in tools.items():
            for hive, path, value_name in entries:
                try:
                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
                    winreg.DeleteValue(key, value_name)
                    self.logger.info(f"已启用{tool}")
                except FileNotFoundError:
                    self.logger.info(f"{tool}已处于启用状态")
                except Exception as e:
                    self.logger.error(f"启用{tool}失败: {str(e)}")

    def _clean_temp_files(self):
        """清理临时文件"""
        temp_paths = [
            os.environ['TEMP'],
            r'C:\Windows\Temp',
            r'C:\Windows\Prefetch'
        ]
        
        cleaned = 0
        for path in temp_paths:
            if os.path.exists(path):
                for root, _, files in os.walk(path):
                    for file in files:
                        try:
                            os.remove(os.path.join(root, file))
                            cleaned += 1
                        except Exception:
                            continue
        self.logger.info(f"清理临时文件完成，共清理{cleaned}个文件")

    def _reset_network(self):
        """重置网络设置"""
        cmds = [
            "ipconfig /flushdns",
            "netsh winsock reset",
            "netsh interface ip reset"
        ]
        
        for cmd in cmds:
            try:
                subprocess.run(cmd, shell=True, check=True)
                self.logger.info(f"执行成功: {cmd}")
            except Exception as e:
                self.logger.error(f"执行失败: {cmd} - {str(e)}")

    def _optimize_performance(self):
        """性能优化"""
        try:
            subprocess.run(
                "powercfg -s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
                shell=True,
                check=True
            )
            self.logger.info("已启用高性能电源计划")
        except Exception as e:
            self.logger.error(f"性能优化失败: {str(e)}")

    # ========== 安全扫描功能 ==========
    def security_scan(self):
        """执行安全扫描"""
        self.logger.info("=== 开始安全扫描 ===")
        killed = self._kill_malicious_processes()
        cleaned = self._clean_autostart_entries()
        quarantined = self._scan_file_system()
        self._generate_report(killed, cleaned, quarantined)
        self.logger.info("=== 安全扫描完成 ===")

    def _kill_malicious_processes(self):
        """终止恶意进程"""
        killed = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_name = proc.info['name'].lower()
                if proc_name in self.malware_db["processes"]:
                    self._kill_process_tree(proc)
                    killed.append(proc_name)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return killed

    def _kill_process_tree(self, proc):
        """终止进程树"""
        try:
            parent = psutil.Process(proc.pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    continue
            parent.kill()
            psutil.wait_procs(children + [parent], timeout=5)
            self.logger.info(f"已终止进程: {proc.info['name']} (PID:{proc.pid})")
        except Exception as e:
            self.logger.error(f"进程终止失败: {str(e)}")

    def _clean_autostart_entries(self):
        """清理自启动项"""
        cleaned = []
        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
        ]
        
        if self.is_64bit:
            registry_paths.append(
                (winreg.HKEY_LOCAL_MACHINE, 
                 r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
            )

        for hive, path in registry_paths:
            try:
                with winreg.OpenKey(hive, path, 0, winreg.KEY_ALL_ACCESS) as key:
                    index = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, index)
                            if self._is_malicious_entry(value):
                                winreg.DeleteValue(key, name)
                                cleaned.append(name)
                                index -= 1
                            index += 1
                        except OSError:
                            break
            except Exception as e:
                self.logger.error(f"注册表清理失败: {path} - {str(e)}")
        
        return cleaned

    def _is_malicious_entry(self, entry):
        """检测恶意条目"""
        entry = entry.lower()
        entry = re.sub(r'^"(.*?)".*', r'\1', entry)
        entry = os.path.expandvars(entry)
        
        for name in self.malware_db["processes"]:
            if name in entry or os.path.basename(name) in entry:
                return True
        return False

    def _scan_file_system(self):
        """文件系统扫描"""
        removed = []
        search_paths = [
            os.environ['WINDIR'],
            os.path.expandvars('%PROGRAMFILES%'),
            os.path.expandvars('%APPDATA%'),
            os.path.expandvars('%TEMP%'),
            r'C:\Windows\Temp'
        ]
        
        for path in search_paths:
            if not os.path.exists(path):
                continue
            
            for root, _, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if self._is_malicious_file(file_path):
                        try:
                            self._quarantine_file(file_path)
                            removed.append(file_path)
                        except Exception as e:
                            self.logger.error(f"文件隔离失败: {file_path} - {str(e)}")
        return removed

    def _is_malicious_file(self, file_path):
        """检测恶意文件"""
        filename = os.path.basename(file_path).lower()
        
        # 文件名匹配
        if filename in self.malware_db["processes"]:
            return True
        
        # 扩展名检测
        if os.path.splitext(filename)[1] in ['.scr', '.pif', '.cmd']:
            return True
        
        # 熵值检测
        try:
            with open(file_path, "rb") as f:
                data = f.read()
                if self._calculate_entropy(data) > 7.5:
                    return True
        except:
            pass
        
        return False

    def _calculate_entropy(self, data):
        """计算信息熵"""
        if not data:
            return 0
        entropy = 0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        for count in counts:
            if count == 0:
                continue
            p = count / len(data)
            entropy -= p * math.log(p, 2)
        return entropy

    def _quarantine_file(self, file_path):
        """隔离文件"""
        dest = os.path.join(
            self.quarantine_dir,
            f"{datetime.now().strftime('%Y%m%d%H%M')}_{os.path.basename(file_path)}"
        )
        try:
            shutil.move(file_path, dest)
            self.logger.info(f"已隔离文件: {file_path} → {dest}")
        except Exception as e:
            raise RuntimeError(f"隔离失败: {str(e)}")

    def _generate_report(self, killed, cleaned, quarantined):
        """生成报告"""
        report = f"""
        ====== 安全扫描报告 {datetime.now()} ======
        处理项目：
        - 终止恶意进程: {len(killed)} 个
        - 清理自启动项: {len(cleaned)} 项
        - 隔离可疑文件: {len(quarantined)} 个
        
        建议操作：
        1. 重启计算机以确保完全清除
        2. 检查系统更新并安装最新补丁
        3. 定期进行安全扫描
        """
        self.logger.info(report)

    # ========== 实时防护功能 ==========
    def realtime_monitor(self):
        """实时防护"""
        self.logger.info("=== 启动实时防护 ===")
        try:
            while True:
                start_time = time.time()
                self._process_scan()
                self._network_protection()
                elapsed = time.time() - start_time
                delay = max(0, random.uniform(*self.scan_intervals) - elapsed)
                time.sleep(delay)
        except KeyboardInterrupt:
            self.logger.info("=== 安全退出实时防护 ===")

    def _process_scan(self):
        """进程扫描"""
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_name = proc.info['name'].lower()
                if proc_name in self.malware_db["processes"]:
                    self._kill_process_tree(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _network_protection(self):
        """网络防护"""
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name().lower()
                    if proc_name in self.malware_db["processes"]:
                        self._block_connection(conn)
                except psutil.NoSuchProcess:
                    continue

    def _block_connection(self, conn):
        """阻断连接"""
        try:
            cmd = (
                f'netsh advfirewall firewall add rule name="Block_{conn.laddr.ip}_{conn.laddr.port}" '
                f'dir=out protocol=TCP localport={conn.laddr.port} action=block'
            )
            subprocess.run(cmd, shell=True, check=True)
            self.logger.info(f"已阻断连接: {conn.laddr.ip}:{conn.laddr.port}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"防火墙规则添加失败: {str(e)}")

# ==================== 主流程控制 ====================
def main():
    # 检查依赖
    missing = check_dependencies()
    if missing:
        install_dependencies(missing)
    
    # 初始化助手
    assistant = ComputerRoomAssistant()
    
    # 处理命令行参数
    if len(sys.argv) == 1:
        print("""使用方法：
        --repair   执行系统修复
        --scan     执行安全扫描
        --monitor  启动实时防护
        """)
        sys.exit()
    
    for arg in sys.argv[1:]:
        if arg == "--repair":
            assistant.system_repair()
        elif arg == "--scan":
            assistant.security_scan()
        elif arg == "--monitor":
            assistant.realtime_monitor()
        else:
            print(f"未知参数: {arg}")
            sys.exit(1)

if __name__ == "__main__":
    # 提权检查
    elevate_privileges()
    
    # 延迟导入依赖
    global psutil, winreg
    import psutil
    import winreg
    
    # 启动主程序
    try:
        main()
    except Exception as e:
        print(f"程序运行出错: {str(e)}")
        input("按回车键退出...")
