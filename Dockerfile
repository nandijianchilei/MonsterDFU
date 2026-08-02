# ===== Build stage =====
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ===== Runtime stage =====
FROM python:3.11-slim

# 安装运行时依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 从 builder 复制 Python 包
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# 复制项目代码
COPY . .

# 安装依赖
RUN pip install -r requirements.txt

# 创建数据目录
RUN mkdir -p data logs config

# 暴露端口
EXPOSE 8000

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=15s \
    CMD curl -f http://localhost:8000/health || exit 1

# 默认启动 web_server（包含全栈服务：Web + 核心引擎 + 抓包）
CMD ["python", "web_server.py"]
