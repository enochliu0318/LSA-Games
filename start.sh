#!/bin/bash
# 启动脚本:自动创建虚拟环境并安装依赖(检查 flask 是否真正可用,而不仅是目录是否存在)
cd "$(dirname "$0")"
PY=python3; command -v python3 >/dev/null || PY=python
if [ ! -x .venv/bin/python ]; then
  rm -rf .venv
  $PY -m venv .venv || { echo "创建虚拟环境失败。Debian/Ubuntu 请先执行: sudo apt install python3-venv"; exit 1; }
fi
if ! .venv/bin/python -c "import flask" 2>/dev/null; then
  echo "正在安装依赖(需要联网)..."
  .venv/bin/python -m ensurepip --upgrade >/dev/null 2>&1
  .venv/bin/python -m pip install -r requirements.txt || { echo "依赖安装失败,请检查网络后重试。"; exit 1; }
fi
exec .venv/bin/python app.py "$@"
