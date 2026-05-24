FROM python:3.11-slim

LABEL maintainer="StrixPro Team <team@strixpro.dev>"
LABEL description="StrixPro - AI-powered security testing platform"

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 复制项目文件
COPY . /app/

# 安装Python依赖
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -e .

# 初始化
RUN mkdir -p /data/output /data/plugins /data/config
RUN strixpro init --output-dir /data/output

# Web服务端口
EXPOSE 8765

# 默认启动Web服务
CMD ["strixpro", "serve", "--port", "8765"]
