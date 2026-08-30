#!/usr/bin/env bash
# xs-bigdan 一键诊断: 卡住/异常时在服务器上跑 `bash ~/xs-bigdan/diag.sh`,
# 把全部输出复制发给 AI 即可远程定位。只读操作,无副作用。
echo "===== 1/6 服务状态 ====="
systemctl is-active xs-bigdan 2>/dev/null || echo "服务未运行!"
uptime
echo
echo "===== 2/6 调度日志(最近25行) ====="
journalctl -u xs-bigdan -n 25 --no-pager 2>/dev/null | tail -25
echo
echo "===== 3/6 任务目录(最近5个) ====="
ls -lt "$HOME/xs-bigdan/runtime/jobs/" 2>/dev/null | head -6
JOB=$(ls -t "$HOME/xs-bigdan/runtime/jobs/" 2>/dev/null | head -1)
if [ -n "$JOB" ] && [ -d "$HOME/xs-bigdan/runtime/jobs/$JOB" ]; then
  echo
  echo "===== 4/6 最新任务 [$JOB] 状态 ====="
  echo "--- runlog 末尾(调度事件) ---"
  tail -5 "$HOME/xs-bigdan/runtime/jobs/$JOB/runlog.jsonl" 2>/dev/null
  echo "--- 最新段日志末尾12行(agent 在干什么) ---"
  LATEST_LOG=$(ls -t "$HOME/xs-bigdan/runtime/jobs/$JOB/"session-*.log 2>/dev/null | head -1)
  [ -n "$LATEST_LOG" ] && tail -12 "$LATEST_LOG"
fi
echo
echo "===== 5/6 相关进程(CPU/内存) ====="
ps aux | grep -E "bigdan\.py|node|chromium" | grep -v grep | awk '{printf "%s  CPU%%=%s MEM%%=%s  %s %s %s\n", $2, $3, $4, $11, $12, $13}' | head -10
echo
echo "===== 6/6 资源水位 ====="
free -h | head -2
df -h / | tail -1
echo
echo "===== 诊断结束: 把以上全部输出发给 AI ====="
echo "===== 7/6 调度器 stdout 末尾(最新任务,真实路径 .webui) ====="
if [ -n "$JOB" ]; then
  tail -15 "$HOME/xs-bigdan/runtime/.webui/bigdan-$JOB.out.log" 2>/dev/null || echo "(无调度器日志)"
fi
