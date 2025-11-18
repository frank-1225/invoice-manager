# invoice-manager
基于Python+Flask+SQLite3的微型电子发票管理系统，通过接入百度智能云实现pdf/图片电子发票自动识别。
本系统通过docker运行，可通过Dockerfile直接构建容器。
docker build -t invoice-manager-backend:latest ./backend
启动容器命令如下，注意做好/app/data和/tmp，两个目录的挂载，确保容器持久化运行。
docker run --name invoice-manager -p 5000:5000 -v {$path}/data:/app/data -v {$path}/tmp:/tmp invoice-manager-backend:latest
