# CoDefenderC3 v8 本机部署

启动 Docker Desktop 后，在 PowerShell 执行：

```powershell
docker load -i D:\GitHub\codefenderc3_v8.tar.gz
docker run -d --name codefender-c3-v8 --restart unless-stopped -p 127.0.0.1:8001:8000 codefender-c3:v8
docker logs --tail 50 codefender-c3-v8
Invoke-RestMethod http://127.0.0.1:8001/readyz
```

镜像内嵌模型和签名库，无需挂载。等待 `/readyz` 返回 `ready: true`。

`web/config.ini` 使用 `/predict-single` HTTP 上传接口。
`include_de = true` 开启反汇编和图特征；设为 `false` 可加快检测，但部分模型可能跳过。
修改配置或后端代码后需重启后端：

```powershell
cd D:\GitHub\NKAMG-AIDefender\web\FastAPI
python main.py
```

前端在 `web/Vue` 执行 `npm run dev`，访问 http://localhost:5173。
链路：前端 → `5005/detect` → Docker `8001/predict-single`。

后端读取 `ScanResult.PerModelScores`、`PerModelPreds` 和 `VirusName`；
集成结果以服务返回的 `IsMalicious` 和 `Score` 为准。
签名库命中会跳过子模型，显示“签名库预检”；实际返回模型数可能少于 33。
模型连接或预测失败返回 HTTP 502。

验证适配器（在 `web/FastAPI` 执行）：

```powershell
python -m unittest discover -s tests -v
```
