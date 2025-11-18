# backend/Dockerfile

FROM python:3.11-slim
WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY app.py .
COPY templates templates/

# 设置环境变量，避免 Python 缓冲
ENV PYTHONUNBUFFERED 1

# 默认 Flask 端口
EXPOSE 5000

# 启动应用
CMD ["python", "app.py"]