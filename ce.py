import os
import winreg
import subprocess

# 恢复 .bat 和 .cmd 文件的关联
def restore_file_association():
    try:
        # 恢复 .bat 和 .cmd 文件扩展名的默认关联
        os.system('assoc .bat=batfile')
        os.system('assoc .cmd=cmdfile')
        print("已恢复 .bat 和 .cmd 文件的默认关联。")
    except Exception as e:
        print(f"恢复文件关联时出错: {e}")

# 启用 CMD
def enable_cmd():
    try:
        # CMD 注册表路径（适用于 Windows 7）
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

# 启用注册表编辑器
def enable_registry_editor():
    try:
        # 注册表编辑器路径（适用于 Windows 7）
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

# 设置 PowerShell 执行策略
def set_powershell_execution_policy():
    try:
        # 设置 PowerShell 执行策略为 RemoteSigned
        subprocess.run(["powershell", "-Command", "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser"], check=True)
        print("PowerShell 执行策略已设置为 RemoteSigned。")
    except subprocess.CalledProcessError as e:
        print(f"设置 PowerShell 执行策略时出错: {e}")

# 恢复文件创建权限
def fix_file_permissions(directory):
    try:
        # 确保用户对目标文件夹具有写入权限
        # 检查目标文件夹是否可写
        test_file = os.path.join(directory, "test_permission.txt")
        with open(test_file, "w") as f:
            f.write("权限测试成功！")
        os.remove(test_file)
        print(f"{directory} 文件夹的写入权限正常。")
    except PermissionError:
        print(f"没有写入权限，请检查文件夹 {directory} 的权限。")
    except Exception as e:
        print(f"文件夹权限检查时出错: {e}")

# 检查并修复文件扩展名和注册表设置
def fix_system():
    print("修复系统设置中...")
    restore_file_association()
    enable_cmd()
    enable_registry_editor()
    set_powershell_execution_policy()
    # 目标文件夹为当前用户的 "Documents" 文件夹
    fix_file_permissions(os.path.expanduser("~\\Documents"))
    print("系统修复完成！")

if __name__ == "__main__":
    fix_system()
