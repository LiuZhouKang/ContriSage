import re
from typing import Dict, List, Set
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class SyscallCategory:
    """系统调用分类"""
    name: str
    description: str
    syscalls: Set[str]
    patterns: List[str] = None  # 正则表达式模式

class SyscallClassifier:
    """系统调用分类器"""
    
    def __init__(self):
        self.categories = self._initialize_categories()
        self._compile_patterns()
    
    def _initialize_categories(self) -> Dict[str, SyscallCategory]:
        """初始化所有系统调用分类"""
        categories = {}
        
        # 1. 网络相关系统调用
        categories['network'] = SyscallCategory(
            name='network',
            description='Network and socket operations',
            syscalls={
                # Socket 基础操作
                'socket', 'socketpair', 'bind', 'listen', 'accept', 'accept4',
                'connect', 'shutdown', 'getsockname', 'getpeername',
                
                # 数据传输
                'send', 'sendto', 'sendmsg', 'sendmmsg', 'recv', 'recvfrom', 
                'recvmsg', 'recvmmsg',
                
                # Socket 选项和控制
                'setsockopt', 'getsockopt', 'socketcall',
                
                # 网络配置和监控
                'ioctl',  # 网络接口配置
                
                # 高级网络功能
                'epoll_create', 'epoll_create1', 'epoll_ctl', 'epoll_wait', 'epoll_pwait',
                'poll', 'ppoll', 'select', 'pselect6',
                
                # Netlink sockets
                'netlink'
            },
            patterns=[
                r'.*socket.*', r'.*net.*', r'.*tcp.*', r'.*udp.*',
                r'.*epoll.*', r'.*poll.*'
            ]
        )
        
        # 2. 文件和I/O相关系统调用
        categories['file'] = SyscallCategory(
            name='file',
            description='File and I/O operations',
            syscalls={
                # 文件打开/关闭
                'open', 'openat', 'openat2', 'close', 'creat',
                
                # 文件读写
                'read', 'write', 'readv', 'writev', 'pread64', 'pwrite64',
                'preadv', 'pwritev', 'preadv2', 'pwritev2',
                
                # 文件位置和属性
                'lseek', 'llseek', '_llseek',
                
                # 文件状态和元数据
                'stat', 'fstat', 'lstat', 'newfstat', 'newstat', 'newlstat',
                'statx', 'fstatfs', 'statfs', 'ustat',
                
                # 文件权限和所有权
                'chmod', 'fchmod', 'fchmodat', 'chown', 'fchown', 'lchown',
                'fchownat',
                
                # 目录操作
                'mkdir', 'mkdirat', 'rmdir', 'getdents', 'getdents64',
                'readdir', 'rewinddir', 'seekdir', 'telldir',
                
                # 文件系统操作
                'link', 'linkat', 'unlink', 'unlinkat', 'symlink', 'symlinkat',
                'readlink', 'readlinkat', 'rename', 'renameat', 'renameat2',
                
                # 文件锁定
                'flock', 'fcntl', 'fcntl64',
                
                # 文件同步
                'sync', 'fsync', 'fdatasync', 'syncfs',
                
                # 特殊文件操作
                'dup', 'dup2', 'dup3', 'pipe', 'pipe2', 'mkfifo', 'mkfifoat',
                'mknod', 'mknodat',
                
                # 文件系统挂载
                'mount', 'umount', 'umount2', 'pivot_root',
                
                # 扩展属性
                'setxattr', 'lsetxattr', 'fsetxattr', 'getxattr', 'lgetxattr',
                'fgetxattr', 'listxattr', 'llistxattr', 'flistxattr',
                'removexattr', 'lremovexattr', 'fremovexattr',
                
                # 文件系统通知
                'inotify_init', 'inotify_init1', 'inotify_add_watch',
                'inotify_rm_watch', 'fanotify_init', 'fanotify_mark'
            },
            patterns=[
                r'.*read.*', r'.*write.*', r'.*open.*', r'.*file.*',
                r'.*dir.*', r'.*stat.*', r'.*link.*', r'.*notify.*'
            ]
        )
        
        # 3. 进程和线程管理
        categories['process_mgmt'] = SyscallCategory(
            name='process_mgmt',
            description='Process and thread management',
            syscalls={
                # 进程创建和执行
                'fork', 'vfork', 'clone', 'clone3', 'execve', 'execveat',
                
                # 进程终止和等待
                'exit', 'exit_group', 'wait4', 'waitpid', 'waitid',
                
                # 进程信号
                'kill', 'tgkill', 'tkill', 'signal', 'sigaction', 'sigprocmask',
                'sigpending', 'sigsuspend', 'sigaltstack', 'sigreturn',
                'rt_sigaction', 'rt_sigprocmask', 'rt_sigpending', 'rt_sigsuspend',
                'rt_sigtimedwait', 'rt_sigqueueinfo', 'rt_sigreturn',
                
                # 进程控制
                'ptrace', 'setpgid', 'getpgid', 'setpgrp', 'getpgrp',
                'setsid', 'getsid',
                
                # 进程资源限制
                'getrlimit', 'setrlimit', 'prlimit64', 'getrusage',
                
                # 进程调度
                'sched_setscheduler', 'sched_getscheduler', 'sched_setparam',
                'sched_getparam', 'sched_setaffinity', 'sched_getaffinity',
                'sched_yield', 'sched_get_priority_max', 'sched_get_priority_min',
                'sched_rr_get_interval',
                
                # 进程和用户标识
                'getpid', 'getppid', 'gettid', 'getuid', 'getgid', 'geteuid',
                'getegid', 'setuid', 'setgid', 'seteuid', 'setegid', 'setreuid',
                'setregid', 'setresuid', 'setresgid', 'getresuid', 'getresgid',
                
                # 进程组和会话
                'setgroups', 'getgroups',
                
                # 线程操作
                'futex', 'set_thread_area', 'get_thread_area', 'set_tid_address'
            },
            patterns=[
                r'.*fork.*', r'.*exec.*', r'.*wait.*', r'.*kill.*',
                r'.*sig.*', r'.*sched.*', r'.*thread.*', r'.*pid.*',
                r'.*uid.*', r'.*gid.*'
            ]
        )
        
        # 4. 内存管理
        categories['memory'] = SyscallCategory(
            name='memory',
            description='Memory management operations',
            syscalls={
                # 内存映射
                'mmap', 'mmap2', 'munmap', 'mremap', 'mprotect', 'mlock',
                'munlock', 'mlockall', 'munlockall', 'madvise', 'mincore',
                'remap_file_pages',
                
                # 堆管理
                'brk', 'sbrk',
                
                # 共享内存
                'shmget', 'shmat', 'shmdt', 'shmctl',
                
                # 内存同步
                'msync', 'mlock2',
                
                # NUMA相关
                'migrate_pages', 'move_pages', 'mbind', 'set_mempolicy',
                'get_mempolicy',
                
                # 内存保护
                'pkey_mprotect', 'pkey_alloc', 'pkey_free'
            },
            patterns=[
                r'.*mmap.*', r'.*brk.*', r'.*shm.*', r'.*mem.*',
                r'.*lock.*'
            ]
        )
        
        # 5. 系统信息和配置
        categories['system_info'] = SyscallCategory(
            name='system_info',
            description='System information and configuration',
            syscalls={
                # 系统信息
                'uname', 'sysinfo', 'times', 'time', 'gettimeofday',
                'settimeofday', 'clock_gettime', 'clock_settime', 'clock_getres',
                'clock_nanosleep', 'timer_create', 'timer_settime', 'timer_gettime',
                'timer_delete', 'timerfd_create', 'timerfd_settime', 'timerfd_gettime',
                
                # 系统配置
                'sysctl', 'prctl', 'arch_prctl', 'personality',
                
                # 资源使用
                'getrusage', 'sysfs',
                
                # 主机名和域名
                'gethostname', 'sethostname', 'getdomainname', 'setdomainname',
                
                # 系统日志
                'syslog',
                
                # 随机数
                'getrandom'
            },
            patterns=[
                r'.*time.*', r'.*clock.*', r'.*timer.*', r'.*sys.*',
                r'.*host.*', r'.*domain.*'
            ]
        )
        
        # 6. 设备和硬件访问
        categories['device_hardware'] = SyscallCategory(
            name='device_hardware',
            description='Device and hardware access',
            syscalls={
                # 设备控制
                'ioctl', 'ioperm', 'iopl',
                
                # 块设备
                'bdflush',
                
                # 终端控制
                'vhangup',
                
                # 硬件特定
                'create_module', 'delete_module', 'init_module', 'finit_module',
                'query_module',
                
                # DMA
                'dma_buf_ioctl'
            },
            patterns=[
                r'.*ioctl.*', r'.*device.*', r'.*hardware.*', r'.*module.*'
            ]
        )
        
        # 7. 安全和权限
        categories['security'] = SyscallCategory(
            name='security',
            description='Security and capability operations',
            syscalls={
                # 能力管理
                'capget', 'capset',
                
                # 安全模块
                'security',
                
                # 密钥管理
                'add_key', 'request_key', 'keyctl',
                
                # 审计
                'audit_write',
                
                # SELinux/AppArmor
                'getcon', 'setcon', 'getpidcon', 'getprevcon',
                
                # 安全计算
                'seccomp'
            },
            patterns=[
                r'.*cap.*', r'.*key.*', r'.*security.*', r'.*audit.*',
                r'.*seccomp.*'
            ]
        )
        
        # 8. IPC (进程间通信)
        categories['ipc'] = SyscallCategory(
            name='ipc',
            description='Inter-process communication',
            syscalls={
                # 消息队列
                'msgget', 'msgsnd', 'msgrcv', 'msgctl',
                
                # 信号量
                'semget', 'semop', 'semctl', 'semtimedop',
                
                # 共享内存 (在memory中也有，但IPC使用更常见)
                'shmget', 'shmat', 'shmdt', 'shmctl',
                
                # 管道
                'pipe', 'pipe2',
                
                # Event文件描述符
                'eventfd', 'eventfd2', 'signalfd', 'signalfd4',
                
                # 定时器文件描述符
                'timerfd_create', 'timerfd_settime', 'timerfd_gettime'
            },
            patterns=[
                r'.*msg.*', r'.*sem.*', r'.*pipe.*', r'.*event.*',
                r'.*signal.*fd.*'
            ]
        )
        
        return categories
    
    def _compile_patterns(self):
        """编译正则表达式模式"""
        for category in self.categories.values():
            if category.patterns:
                category.compiled_patterns = [
                    re.compile(pattern, re.IGNORECASE) 
                    for pattern in category.patterns
                ]
    
    def classify_syscall(self, syscall_name: str) -> List[str]:
        """
        分类单个系统调用
        
        Args:
            syscall_name: 系统调用名称
            
        Returns:
            匹配的分类列表
        """
        matches = []
        syscall_clean = syscall_name.lower().strip()
        
        for category_name, category in self.categories.items():
            # 首先检查精确匹配
            if syscall_clean in category.syscalls:
                matches.append(category_name)
                continue
            
            # 然后检查模式匹配
            if hasattr(category, 'compiled_patterns'):
                for pattern in category.compiled_patterns:
                    if pattern.search(syscall_clean):
                        matches.append(category_name)
                        break
        
        # 如果没有匹配到任何分类，标记为未知
        if not matches:
            matches.append('unknown')
        
        return matches
    
    def get_category_features(self, syscall_df) -> Dict[str, int]:
        """
        基于分类计算特征
        
        Args:
            syscall_df: 包含系统调用数据的DataFrame
            
        Returns:
            按分类统计的特征字典
        """
        features = {}
        
        # 初始化所有分类的计数器
        for category_name in self.categories.keys():
            features[f'{category_name}_syscall_count'] = 0
            features[f'{category_name}_syscall_types'] = 0
        
        features['unknown_syscall_count'] = 0
        features['unknown_syscall_types'] = 0
        
        if len(syscall_df) == 0:
            return features
        
        # 统计每个系统调用的分类
        syscall_stats = syscall_df.groupby('syscall_name')['occur_times'].sum()
        
        classified_syscalls = {}
        for syscall_name in syscall_stats.index:
            categories = self.classify_syscall(syscall_name)
            classified_syscalls[syscall_name] = categories
        
        # 计算每个分类的统计信息
        for syscall_name, occur_times in syscall_stats.items():
            categories = classified_syscalls[syscall_name]
            
            for category in categories:
                features[f'{category}_syscall_count'] += occur_times
                features[f'{category}_syscall_types'] += 1
        
        # 计算比例特征
        total_syscalls = syscall_df['occur_times'].sum()
        if total_syscalls > 0:
            for category_name in self.categories.keys():
                count_key = f'{category_name}_syscall_count'
                ratio_key = f'{category_name}_syscall_ratio'
                features[ratio_key] = features[count_key] / total_syscalls
            
            features['unknown_syscall_ratio'] = features['unknown_syscall_count'] / total_syscalls
        
        return features
    
    def get_syscall_distribution(self, syscall_df) -> Dict[str, Dict]:
        """
        获取系统调用分布统计
        
        Args:
            syscall_df: 包含系统调用数据的DataFrame
            
        Returns:
            详细的分布统计信息
        """
        distribution = {}
        
        if len(syscall_df) == 0:
            return distribution
        
        syscall_stats = syscall_df.groupby('syscall_name')['occur_times'].sum().sort_values(ascending=False)
        
        for category_name, category in self.categories.items():
            category_syscalls = {}
            category_total = 0
            
            for syscall_name, count in syscall_stats.items():
                if self.classify_syscall(syscall_name)[0] == category_name:
                    category_syscalls[syscall_name] = count
                    category_total += count
            
            distribution[category_name] = {
                'syscalls': category_syscalls,
                'total_count': category_total,
                'unique_types': len(category_syscalls),
                'top_syscalls': dict(list(category_syscalls.items())[:5])
            }
        
        return distribution
    
    def print_classification_report(self, syscall_df):
        """打印分类报告"""
        distribution = self.get_syscall_distribution(syscall_df)
        total_syscalls = syscall_df['occur_times'].sum()
        
        print("\n" + "="*80)
        print("系统调用分类报告")
        print("="*80)
        
        for category_name, stats in distribution.items():
            if stats['total_count'] > 0:
                percentage = (stats['total_count'] / total_syscalls) * 100
                print(f"\n{category_name.upper()} ({stats['total_count']:,} calls, {percentage:.1f}%)")
                print(f"  独特系统调用类型: {stats['unique_types']}")
                print("  TOP 5 系统调用:")
                for syscall, count in stats['top_syscalls'].items():
                    print(f"    {syscall}: {count:,}")
