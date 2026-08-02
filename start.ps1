# DFU Prototype - One-Click Start (PowerShell)
$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot

Write-Host "============================================"
Write-Host "  DFU Prototype - One-Click Start"
Write-Host "============================================"

# 1. 检查 python 可用
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "[ERROR] 未找到 python，请先安装 Python 3.10+ 并加入 PATH。" -ForegroundColor Red
    Read-Host "按回车退出"
    exit 1
}

# 2. 自动安装缺失依赖
Write-Host "[1/3] 检查依赖..."
python -m pip install -r requirements.txt --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "[WARN] 依赖安装出现错误，尝试继续启动..." -ForegroundColor Yellow
}

# 3. 启动 web_server.py（新窗口，便于查看 Token 日志）
Write-Host "[2/3] 启动 web_server.py ..."
Start-Process python -ArgumentList "web_server.py" -WorkingDirectory $PSScriptRoot

# 4. 等待服务就绪并打开浏览器
Write-Host "[3/3] 等待服务就绪..."
Start-Sleep -Seconds 3
Start-Process "http://127.0.0.1:8000/monster"

Write-Host ""
Write-Host "已启动，浏览器将打开 http://127.0.0.1:8000/monster"
Write-Host "若未设置 DFU_WEB_TOKEN，Token 会打印在服务器控制台窗口。"
