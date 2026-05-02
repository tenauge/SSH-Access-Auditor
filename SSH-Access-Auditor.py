#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys
import re
from datetime import datetime, timedelta
from collections import defaultdict
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

def parse_args():
    # 使用示例
    examples = """
使用示例:
  1. 基础分析并生成报告:
     python SSH-Access-Auditor.py ./auth.log -o report.txt

  2. 筛选登录成功的记录:
     python SSH-Access-Auditor.py ./auth.log -a
     
  3. 筛选登录失败的记录:
     python SSH-Access-Auditor.py ./auth.log -f

  4. 筛选特定时间段内，以password方式登录的尝试:
     python SSH-Access-Auditor.py ./auth.log -a -f -p -ts "12/24 03:00:00" -te "12/24 23:00:00"

  5. 查看最近 7 天的失败记录并统计 IP:
     python SSH-Access-Auditor.py ./auth.log -f -tr 7
"""
    
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=examples
    )

    # 必填位置参数
    parser.add_argument("logfile", help="指定要分析的日志文件路径 (例如: ./auth.log)")

    # 状态过滤选项组（不互斥，因为可能会同时需要屏幕输出和文件报告）
    parser.add_argument("-a", "--accepted", action="store_true", help="在屏幕显示认证成功的登录记录及统计信息")
    parser.add_argument("-f", "--failed", action="store_true", help="在屏幕显示认证失败的登录尝试及统计信息")

    # 认证方式过滤
    parser.add_argument("-k", "--key", action="store_true", help="仅在屏幕输出中过滤基于公钥 (publicKey) 的认证")
    parser.add_argument("-p", "--password", action="store_true", help="仅在屏幕输出中过滤基于密码 (password) 的认证")
    parser.add_argument("-P", "--pam", action="store_true", help="仅在屏幕输出中过滤基于键盘交互/PAM的认证")

    # 时间过滤参数
    parser.add_argument("-t", "--time", dest="exact_date", help="按指定日期筛选 (例如: -t \"12/23\")")
    parser.add_argument("-ts", "--time-start", dest="time_start", help="按起始时间筛选 (例如: -ts \"12/23 03:00:00\")")
    parser.add_argument("-te", "--time-end", dest="time_end", help="按结束时间筛选 (例如: -te \"12/23 23:00:00\")")
    parser.add_argument("-tr", "--time-recent", dest="time_recent", type=int, help="显示最近 X 天的记录 (例如: -tr 7 显示近7天)")

    # 输出综合报告参数
    parser.add_argument("-o", "--output", dest="outfile", help="生成综合应急排查分析报告并输出到指定文件")

    return parser.parse_args()

def parse_user_time(t_str, is_exact_date=False):
    """解析用户在命令行输入的时间格式，统一使用1900年作为基准年便于比较"""
    try:
        if is_exact_date:
            return datetime.strptime(t_str, "%m/%d")
        else:
            return datetime.strptime(t_str, "%m/%d %H:%M:%S")
    except ValueError:
        print(f"错误: 时间格式不正确 '{t_str}'")
        sys.exit(1)

def parse_log_time(t_str):
    """解析 syslog 标准时间格式 (例如: Dec 23 03:26:13)"""
    try:
        return datetime.strptime(t_str, "%b %d %H:%M:%S")
    except ValueError:
        return None

def main():
    args = parse_args()

    if not os.path.isfile(args.logfile):
        print(f"错误: 找不到日志文件 '{args.logfile}'")
        sys.exit(1)

    # 预处理时间条件
    target_date = parse_user_time(args.exact_date, is_exact_date=True) if args.exact_date else None
    start_time = parse_user_time(args.time_start) if args.time_start else None
    end_time = parse_user_time(args.time_end) if args.time_end else None
    
    # 获取日志中的最大时间点，用于计算 -tr (最近几天)
    max_log_time = None
    if args.time_recent:
        try:
            with open(args.logfile, "r", encoding="utf-8", errors="ignore") as file:
                for line in file:
                    time_match = re.search(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
                    if time_match:
                        log_time = parse_log_time(time_match.group(1))
                        if log_time:
                            if max_log_time is None or log_time > max_log_time:
                                max_log_time = log_time
        except Exception as e:
            pass

    # 用于保存所有符合时间筛选条件的数据结构
    accepted_events = []
    failed_events = []

    # 正则提取日志关键信息
    # 匹配时间开头
    time_pattern = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")
    # 匹配 sshd 日志行为，使用 (?:invalid user )? 兼容有效用户和无效用户的失败日志
    ssh_action_pattern = re.compile(
        r"sshd\[\d+\]: (Accepted|Failed) (password|publickey|keyboard-interactive/pam).*? for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
    )

    try:
        with open(args.logfile, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                line = line.strip()
                if "sshd[" not in line:
                    continue

                time_match = time_pattern.search(line)
                if not time_match:
                    continue
                
                log_time_str = time_match.group(1)
                log_time = parse_log_time(log_time_str)
                if not log_time:
                    continue

                # 1. 检验时间过滤条件
                if target_date:
                    if log_time.month != target_date.month or log_time.day != target_date.day:
                        continue
                if start_time and log_time < start_time:
                    continue
                if end_time and log_time > end_time:
                    continue
                if args.time_recent and max_log_time:
                    # 如果记录时间距离最新时间超过限定天数，则跳过
                    if max_log_time - log_time > timedelta(days=args.time_recent):
                        continue

                # 2. 检验日志内容特征
                action_match = ssh_action_pattern.search(line)
                if action_match:
                    status = action_match.group(1)  # Accepted 或 Failed
                    method = action_match.group(2)  # password, publickey 等
                    user = action_match.group(3)    # 用户名
                    ip = action_match.group(4)      # IP地址
                    
                    # 格式化日期和具体时间供后续分组展示
                    # 避免"Dec 03"与"Dec  3"差异，统一由 datetime 转换
                    fmt_date = log_time.strftime("%b %d").replace(" 0", " ") 
                    fmt_time = log_time.strftime("%H:%M:%S")

                    event_data = {
                        "raw": line,
                        "date": fmt_date,
                        "time": fmt_time,
                        "method": method,
                        "user": user,
                        "ip": ip
                    }

                    if status == "Accepted":
                        accepted_events.append(event_data)
                    elif status == "Failed":
                        failed_events.append(event_data)
    except Exception as e:
        print(f"读取或解析日志文件时发生错误: {e}")
        sys.exit(1)


    # ================= 终端输出逻辑 (-a 参数优化) =================
    if args.accepted:
        # 获取筛选类型
        filter_methods = []
        if args.key: filter_methods.append("publickey")
        if args.password: filter_methods.append("password")
        if args.pam: filter_methods.append("keyboard-interactive/pam")
        
        print(f"\n=================================== 登录成功 ===================================")
        
        # 过滤需要的事件
        display_acc_events = [e for e in accepted_events if not filter_methods or e["method"] in filter_methods]

        for e in display_acc_events:
            print(e["raw"])
        
        filter_cond_str = "Accepted"
        if filter_methods:
            filter_cond_str += f" {', '.join(filter_methods)}"
        print(f"\n总计: {len(display_acc_events)} 条成功的 SSH 登录记录 (过滤条件: {filter_cond_str})\n")

        # 将成功记录分类汇总
        method_map = {
            "password": "password",
            "publickey": "publicKey",
            "keyboard-interactive/pam": "键盘PAM交互"
        }
        
        for raw_method, zh_method in method_map.items():
            method_events = [e for e in display_acc_events if e["method"] == raw_method]
            if method_events:
                print(f"基于 {zh_method} 登录的共 {len(method_events)} 条：")
                # 按日期聚合
                date_groups = defaultdict(list)
                for e in method_events:
                    date_groups[e["date"]].append(e)
                
                # 按日期输出
                for d_key, events_in_date in sorted(date_groups.items()):
                    print(f"{d_key}：")
                    for ev in events_in_date:
                        print(f"[{ev['time']}] {ev['ip']} {ev['user']}")
                print("") # 留空行隔离不同类型

    # ================= 终端输出逻辑 (-f 参数优化) =================
    if args.failed:
        filter_methods = []
        if args.key: filter_methods.append("publickey")
        if args.password: filter_methods.append("password")
        if args.pam: filter_methods.append("keyboard-interactive/pam")

        display_fail_events = [e for e in failed_events if not filter_methods or e["method"] in filter_methods]

        print(f"\n=================================== 登录失败 ===================================")
        
        if not args.accepted:  # 若同时用了-a，上面已经打印过头部了
            print(f"--- SSH日志分析结果 ({args.logfile}) ---")
        for e in display_fail_events:
            print(e["raw"])
        
        filter_cond_str = "Failed"
        if filter_methods:
            filter_cond_str += f" {', '.join(filter_methods)}"
        print(f"\n总计: {len(display_fail_events)} 条失败的 SSH 登录记录 (过滤条件: {filter_cond_str})\n")

        # 按日期和 IP 统计爆破次数
        date_ip_counts = defaultdict(lambda: defaultdict(int))
        for e in display_fail_events:
            date_ip_counts[e["date"]][e["ip"]] += 1
        
        for d_key in sorted(date_ip_counts.keys()):
            print(f"{d_key}：")
            # 针对当天该IP失败次数进行降序排序
            sorted_ips = sorted(date_ip_counts[d_key].items(), key=lambda item: item[1], reverse=True)
            for ip, count in sorted_ips:
                print(f"{ip} - {count} 次")
            print("")

    # ================= 文件输出逻辑 (-o 参数优化：应急排查综合报告) =================
    if args.outfile:
        # 基于时间过滤后的全部记录进行综合统计分析 (忽略 -p, -k, -P，因为要完整画像)
        
        # 1. 统计总体失败次数
        ip_total_fails = defaultdict(int)
        for e in failed_events:
            ip_total_fails[e["ip"]] += 1
        
        # 2. 计算存在爆破行为的 IP (> 10 次)
        brute_force_ips = {ip: count for ip, count in ip_total_fails.items() if count > 10}
        brute_force_str_list = [f"{ip}（{count}次）" for ip, count in sorted(brute_force_ips.items(), key=lambda x: x[1], reverse=True)]
        
        # 3. 计算疑似爆破成功的 IP (在爆破名单中，并且存在成功登录的记录)
        successful_ips = set(e["ip"] for e in accepted_events)
        compromised_ips = set(brute_force_ips.keys()).intersection(successful_ips)
        
        # 4. 提取所有出现的日期，便于时间线输出
        all_dates = set([e["date"] for e in accepted_events] + [e["date"] for e in failed_events])
        
        report_lines = []
        # 输出总体结论
        bf_display = "，".join(brute_force_str_list) if brute_force_str_list else "无"
        comp_display = "，".join(list(compromised_ips)) if compromised_ips else "无"
        
        report_lines.append(f"存在爆破行为的 IP：{bf_display}")
        report_lines.append(f"疑似爆破成功的 IP：{comp_display}")
        report_lines.append("")

        # 按时间线展示详情
        # 准备按日期归总的数据字典
        acc_by_date = defaultdict(list)
        for e in accepted_events:
            acc_by_date[e["date"]].append(e)
            
        fail_by_date = defaultdict(list)
        for e in failed_events:
            fail_by_date[e["date"]].append(e)

        def sort_date_str(date_str):
            # 将 "Dec 23" 转为比较可用的日期对象用于排序
            return datetime.strptime(date_str, "%b %d")

        for current_date in sorted(all_dates, key=sort_date_str):
            report_lines.append(current_date)
            
            # 当日成功的记录
            report_lines.append("登录成功的记录")
            if current_date in acc_by_date:
                for e in acc_by_date[current_date]:
                    # 格式：[时间] IP 用户（认证方式）
                    report_lines.append(f"[{e['time']}] {e['ip']} {e['user']}（{e['method']}）")
            else:
                report_lines.append("无")
            report_lines.append("")

            # 当日失败的记录统计
            report_lines.append("登录失败的记录")
            if current_date in fail_by_date:
                day_fails = defaultdict(int)
                for e in fail_by_date[current_date]:
                    day_fails[e["ip"]] += 1
                sorted_day_fails = sorted(day_fails.items(), key=lambda item: item[1], reverse=True)
                for ip, count in sorted_day_fails:
                    report_lines.append(f"{ip} - {count} 次")
            else:
                report_lines.append("无")
            
            report_lines.append("") # 日期块之间的空行分隔
        
        # 写入文件
        try:
            with open(args.outfile, "w", encoding="utf-8") as out_f:
                out_f.write("\n".join(report_lines))
            print(f"综合排查报告已成功生成至: {args.outfile}")
        except Exception as e:
            print(f"写入报告文件时发生错误: {e}")

if __name__ == "__main__":
    main()