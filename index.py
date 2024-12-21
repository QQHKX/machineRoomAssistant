import psutil
import winreg
import time

def enable_cmd():
    try:
        # CMD 注册表路径
        reg_path = r"Software\Policies\Microsoft\Windows\System"
        
        # 打开注册表键
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE) as registry_key:
            try:
                # 删除 DisableCMD 键值
                winreg.DeleteValue(registry_key, "DisableCMD")
                print("CMD 已成功启用。")
            except FileNotFoundError:
                print("DisableCMD 键不存在，CMD 已启用。")
    except PermissionError:
        print("权限不足，请以管理员身份运行该脚本。")
    except Exception as e:
        print(f"启用 CMD 时发生错误: {e}")

def enable_registry_editor():
    try:
        # 注册表编辑器路径
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
        
        # 打开注册表键
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE) as registry_key:
            try:
                # 删除 DisableRegistryTools 键值
                winreg.DeleteValue(registry_key, "DisableRegistryTools")
                print("注册表编辑器已成功启用。")
            except FileNotFoundError:
                print("DisableRegistryTools 键不存在，注册表编辑器已启用。")
    except PermissionError:
        print("权限不足，请以管理员身份运行该脚本。")
    except Exception as e:
        print(f"启用注册表编辑器时发生错误: {e}")

# 检测并强制结束恶意进程
def kill_malicious_process(process_name):
    """
    检查并结束指定的恶意进程
    :param process_name: 进程名称
    """
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'].lower() == process_name.lower():
                proc.kill()  # 强制结束进程
                print(f"已强制结束恶意进程: {proc.info['name']} (PID: {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue  # 处理异常

# 阻止恶意软件的自启动
def remove_malicious_startup(process_name):
    """
    阻止指定的恶意程序自启动项
    :param process_name: 进程名称
    """
    registry_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",  # 64位系统的32位程序
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    ]
    
    for path in registry_paths:
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ | winreg.KEY_WRITE)
            i = 0
            while True:
                try:
                    # 获取所有注册表项
                    name, value, _ = winreg.EnumValue(registry_key, i)
                    if process_name.lower() in value.lower():
                        print(f"发现恶意自启动项: {name} -> {value}")
                        # 删除注册表中的恶意程序自启动项
                        winreg.DeleteValue(registry_key, name)
                        print(f"已删除恶意自启动项: {name}")
                    i += 1
                except OSError:
                    break
        except Exception as e:
            print(f"无法访问注册表路径 {path}: {e}")

# 监控系统进程和自启动项
def monitor_system(malicious_process_names):
    """
    监控系统，检查并处理多个恶意进程和自启动项
    :param malicious_process_names: 需要监控的恶意进程名称列表
    """
    while True:
        for process_name in malicious_process_names:
            # 1. 检查并杀死恶意进程
            kill_malicious_process(process_name)

            # 2. 检查并删除恶意自启动项
            remove_malicious_startup(process_name)

            # 3. 输出当前监控状态
            print(f"正在监控系统中的恶意进程：{process_name} ...")
        
        # 每10秒检查一次
        time.sleep()

# 启动系统监控
if __name__ == "__main__":
    print("机房助手已启动")
    print("正在启用 CMD 和注册表编辑器...")

    # 启用 CMD 和注册表编辑器
    enable_cmd()
    enable_registry_editor()

    print("准备开始结束恶意进程和自启动项...")

    # 设置恶意进程的名称列表
    malicious_process_names = [
        "jfglzs.exe",
        "zmserv.exe",
        "srvany.exe",
        "StudentMain.exe",
        "GATESRV.exe",
        "ProcHelper64.exe",
        "MasterHelper.exe"
    ]

    print(f"开始监控这些恶意进程: {', '.join(malicious_process_names)} ...")
    monitor_system(malicious_process_names)
