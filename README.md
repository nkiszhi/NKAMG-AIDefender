# Codefender 多模型恶意文件检测

腾讯云 Ubuntu 部署请按 [web/TENCENT_DEPLOY.md](web/TENCENT_DEPLOY.md) 执行：前端 9528、后端 5006、模型服务本机 8001。

> 当前本机部署使用 `D:\GitHub\codefenderc3_v8.tar.gz`，实际镜像标签为 `codefender:latest`。
> 最新部署与接口配置见 [web/DOCKER_V8.md](web/DOCKER_V8.md)。下方 `peng233/codefender:v2` 步骤为旧版说明，不能直接用于当前 v8 配置。

Codefender 是一个独立的 PE 样本恶意文件检测 Web 项目。系统由三部分组成：

- 前端：Vue3 + Element Plus，提供样本上传、基础信息展示、PE 结构展示和模型结果展示。
- 后端：FastAPI，负责文件上传、PE 结构校验、基础信息计算、模型服务适配。
- 模型服务：Docker 镜像 `peng233/codefender:v2`，提供 33 个检测模型的扫描能力。

用户上传待检样本后，后端会先判断文件是否为有效 PE 样本；只有通过 PE 结构校验的文件才会提交给模型服务检测。

## 检测流程

1. 用户在网页上传待检 PE 样本。
2. 后端计算 SHA256、MD5、文件大小、文件类型。
3. 后端校验 PE 结构：`MZ` 头、`PE\0\0` 签名、COFF 文件头、PE32/PE32+ 可选头。
4. 后端提取 PE 基础信息：架构、入口点、镜像基址、子系统、节数量、编译时间、节表等。
5. 后端把有效 PE 样本提交给 Codefender Docker 模型服务。
6. 前端展示基础信息、PE 结构信息、33 个模型结果和集成结果。

非 PE 文件会被后端拒绝，不会继续提交给模型检测。

## 支持模型

当前模型清单共 33 个。

| 模型 | 参考文献 |
|---|---|
| MalConv | Raff E, Barker J, Sylvester J, et al. Malware Detection by Eating a Whole EXE. AAAI Workshop on Artificial Intelligence for Cyber Security, 2018. [arXiv:1710.09435](https://arxiv.org/abs/1710.09435) |
| MalConv2 | Raff E, Fleshman W, Zak R, et al. Classifying Sequences of Extreme Length with Constant Memory Applied to Malware Detection. AAAI, 2021. [arXiv:2012.09390](https://arxiv.org/abs/2012.09390) |
| ByteTransformer | Vaswani A, Shazeer N, Parmar N, et al. Attention Is All You Need. NeurIPS, 2017. [arXiv:1706.03762](https://arxiv.org/abs/1706.03762) |
| SaxeBerlinDNN | Saxe J, Berlin K. Deep Neural Network Based Malware Detection Using Two-Dimensional Binary Visualization. IEEE ISI, 2015. [doi:10.1109/ISI.2015.7165944](https://doi.org/10.1109/ISI.2015.7165944) |
| EmberDNN | Anderson H S, Roth P. EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models. KDD Workshop, 2018. [arXiv:1804.04637](https://arxiv.org/abs/1804.04637) |
| NatarajKNN | Nataraj L, Karthikeyan S, Jacob G, et al. Malware Images: Visualization and Automatic Classification. VizSec, 2011. [doi:10.1145/2016904.2016908](https://doi.org/10.1145/2016904.2016908) |
| DrebinSVM | Arp D, Spreitzenbarth M, Hübner M, et al. DREBIN: Effective and Explainable Detection of Android Malware in Your Pocket. NDSS, 2014. [ndss-symposium.org](https://www.ndss-symposium.org/ndss-paper/drebin-effective-and-explainable-detection-of-android-malware-in-your-pocket/) |
| DL4MD | Hardy W, Chen L, Hou S, et al. DL4MD: A Deep Learning Framework for Intelligent Malware Detection. DMIN, 2016. [doi:10.1109/DMIN.2016.9](https://doi.org/10.1109/DMIN.2016.9) |
| PEMinerRF | Shafiq M Z, Tabish S M, Mirza F, et al. PE-Miner: Mining Structural Information to Detect Malicious Executables in Realtime. RAID, 2009. [doi:10.1007/978-3-642-04342-0_1](https://doi.org/10.1007/978-3-642-04342-0_1) |
| DrebinImport | Arp D, et al. DREBIN: Effective and Explainable Detection of Android Malware in Your Pocket. NDSS, 2014. [ndss-symposium.org](https://www.ndss-symposium.org/ndss-paper/drebin-effective-and-explainable-detection-of-android-malware-in-your-pocket/) |
| ALOHANet | Aghakhani H, Gritti F, Mecca F, et al. When Malware is Packin' Heat; Limits of Machine Learning Classifiers Based on Static Analysis Features. USENIX Security, 2020. [usenix.org](https://www.usenix.org/conference/usenixsecurity20/presentation/aghakhani) |
| EmberGBDT_Import | Anderson H S, Roth P. EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models. KDD Workshop, 2018. [arXiv:1804.04637](https://arxiv.org/abs/1804.04637) |
| RaffFeatureNet | Raff E, et al. Malware Detection by Eating a Whole EXE. AAAI Workshop, 2018. [arXiv:1710.09435](https://arxiv.org/abs/1710.09435) |
| DrebinString | Arp D, et al. DREBIN: Effective and Explainable Detection of Android Malware in Your Pocket. NDSS, 2014. [ndss-symposium.org](https://www.ndss-symposium.org/ndss-paper/drebin-effective-and-explainable-detection-of-android-malware-in-your-pocket/) |
| OpcodeLSTM | Deep Android Malware Detection. IEEE Transactions on Information Forensics and Security, 2017. [doi:10.1109/TIFS.2017.2713418](https://doi.org/10.1109/TIFS.2017.2713418) |
| OpcodeTransformer | Ren Z, Wu H, Ning Q, et al. End-to-end Malware Detection for Android IoT Devices Using Deep Learning. IEEE Access, 2020. [doi:10.1109/ACCESS.2020.2993370](https://doi.org/10.1109/ACCESS.2020.2993370) |
| OpcodeStatNet | Ahmadi M, Ulyanov D, Semenov S, et al. Novel Feature Extraction, Selection and Fusion for Effective Malware Family Classification. ACM CODASPY, 2016. [doi:10.1145/2857705.2857713](https://doi.org/10.1145/2857705.2857713) |
| AsmEmbedNet | Ding S Y H, Fung B C M, Charland P. Asm2Vec: Boosting Static Representation Robustness for Binary Clone Search against Code Obfuscation and Compiler Optimization. IEEE S&P, 2019. [doi:10.1109/SP.2019.00003](https://doi.org/10.1109/SP.2019.00003) |
| MalGraph | Ling X, Wu L, Deng W, et al. MalGraph: Hierarchical Graph Neural Networks for Robust Windows Malware Detection. IEEE INFOCOM, 2022. [github.com/ryderling/MalGraph](https://github.com/ryderling/MalGraph) |
| CFGGAT | Yan J, Yan G, Jin D. Classifying Malware Represented as Control Flow Graphs Using Deep Graph CNN. IEEE DSN, 2019. [doi:10.1109/DSC47296.2019](https://doi.org/10.1109/DSC47296.2019) |
| CFGGCN | Kipf T N, Welling M. Semi-Supervised Classification with Graph Convolutional Networks. ICLR, 2017. [arXiv:1609.02907](https://arxiv.org/abs/1609.02907) |
| CFGDGCNN | Zhang M, Cui Z, Neumann M, et al. An End-to-End Deep Learning Architecture for Graph Classification. AAAI, 2018. [doi:10.1609/aaai.v32i1.11782](https://doi.org/10.1609/aaai.v32i1.11782) |
| CallGraphGNN | Li Y, Gu C, Dullien T, et al. Graph Matching Networks for Learning the Similarity of Graph Structured Objects. ICML, 2019. [arXiv:1904.12787](https://arxiv.org/abs/1904.12787) |
| GraphStatNet | Kinable J, Kostakis O. Malware Classification Based on Call Graph Clustering. Journal in Computer Virology, 7(4):233-245, 2011. [doi:10.1007/s11416-011-0151-y](https://doi.org/10.1007/s11416-011-0151-y) |
| GrayscaleCNN | Nataraj L, et al. Malware Images: Visualization and Automatic Classification. VizSec, 2011. [doi:10.1145/2016904.2016908](https://doi.org/10.1145/2016904.2016908) |
| InceptionV3 | Nataraj L, et al. Malware Images（VizSec 2011）可视化方法 + Szegedy C, Vanhoucke V, Ioffe S, et al. Rethinking the Inception Architecture for Computer Vision. CVPR, 2016. [arXiv:1512.00567](https://arxiv.org/abs/1512.00567) |
| IMCFN | Vasan D, Alazab M, Wassan S, et al. IMCFN: Image-based Malware Classification Using Fine-tuned Convolutional Neural Network Architecture. Computer Networks, 171:107138, 2020. [doi:10.1016/j.comnet.2020.107138](https://doi.org/10.1016/j.comnet.2020.107138) |
| ColorCNN | Fu J, Xue J, Wang Y, et al. Malware Visualization for Fine-Grained Classification. IEEE Access, 6:14510–14523, 2018. [doi:10.1109/ACCESS.2018.2805301](https://doi.org/10.1109/ACCESS.2018.2805301) |
| MarkovCNN | Malware Identification Using Visualization Images and Deep Learning. Computers & Security, 2018. [doi:10.1016/j.cose.2018.09.001](https://doi.org/10.1016/j.cose.2018.09.001) |
| EntropyMapCNN | Conti M, et al. Visual Reverse Engineering of Binary and Data Files. VizSec. [doi:10.1007/978-3-319-73198-8_1](https://doi.org/10.1007/978-3-319-73198-8_1) |
| HashEmbedNet | Towards Interpretable and Robust ML-based Malware Detection. CCS Workshop on AI for Security, 2019. [doi:10.1145/3338466.3358907](https://doi.org/10.1145/3338466.3358907) |
| MetadataNet | Shafiq M Z, Tabish S M, Mirza F, et al. PE-Miner: Mining Structural Information to Detect Malicious Executables in Realtime. In: Recent Advances in Intrusion Detection (RAID), LNCS 5758, pp. 121-141, 2009. [doi:10.1007/978-3-642-04342-0_1](https://doi.org/10.1007/978-3-642-04342-0_1) |
| ResourceNet | Ahmadi M, Ulyanov D, Semenov S, et al. Novel Feature Extraction, Selection and Fusion for Effective Malware Family Classification. ACM CODASPY, 2016. [doi:10.1145/2857705.2857713](https://doi.org/10.1145/2857705.2857713) |

### 模型优化要点

1. **维度对齐重训**：11 个模型的权重维度与线上特征维度不一致，这些票近似噪声。

| 模型 | 注册维度（线上输入） | 权重实际维度 | 差异 |
|:-:|:--:|:--:|:-:|
| SaxeBerlinDNN | 512 | 776 | +264 |
| EmberDNN | 512 | 776 | +264 |
| NatarajKNN | 512 | 776（近邻库 3,339 行） | +264 |
| DrebinSVM | 327 | 264 | −63 |
| DL4MD | 327 | 264 | −63 |
| DrebinImport | 1280 | 339 | −941 |
| ALOHANet | 1280 | 339 | −941 |
| RaffFeatureNet | 104 | 553 | +449 |
| DrebinString | 104 | 553 | +449 |
| MetadataNet | 158 | 60 | −98 |
| HashEmbedNet | 512 | 64（4 路 Embedding 结构，输入类型不符） | 类型不符 |

错位成对出现：DrebinImport/ALOHANet 同错成 339，RaffFeatureNet/DrebinString 同错成 553——同一视角的模型是在同一份错误切片上训练的。PEMinerRF 另有疑点：30 棵树的最大分裂特征下标为 104，未按完整 327 维训练。

2. **字节模型截断**：MalConv/MalConv2/ByteTransformer 只读文件头（32KB/2MB），大文件欠拟合。
3. **操作码词表固定**：当前用 `crc32` 哈希桶当词表，重训前后词表漂移。
4. **伪图模型不吃边**：CFGGAT/CFGGCN/CFGDGCNN/CallGraphGNN 推理时是同一个 22 维统计上的 MLP，不是图模型。

前端页面会通过后端 `/models` 接口显示模型清单。

## 目录结构

```text
web/
  FastAPI/   FastAPI 后端，提供上传检测、PE结构分析和模型服务适配
  Vue/       Vue3 + Element Plus 单页前端
    public/config.ini  浏览器访问后端的地址配置
  config.ini 后端、Docker 模型服务和跨容器路径配置
CoDefenderC3/ 模型推理服务及训练代码
```

## 环境要求

- Docker Desktop 或 Docker Engine
- Python 3.10+
- Node.js 18+ 和 npm
- Windows PowerShell、Linux shell 或 macOS shell 均可运行

## 部署步骤

### 1. 获取代码

```powershell
cd C:\zjp\github
git clone https://github.com/nkiszhi/NKAMG-AIDefender.git
cd C:\zjp\github\NKAMG-AIDefender
```

### 2. 启动 Codefender 模型服务	

拉取公开 Docker 镜像：

```powershell
docker pull peng233/codefender:v2
```

启动模型服务：

```powershell
docker run -d --name codefender-api -p 8001:8000 peng233/codefender:v2
```

验证模型服务：

```powershell
curl http://127.0.0.1:8001/health
curl http://127.0.0.1:8001/openapi.json
```

如果容器名不是 `codefender-api`，需要修改 `web/config.ini`：

```ini
[docker]
container_name = 实际容器名
container_upload_dir = /tmp/codefender_uploads
```

查看实际容器名：

```powershell
docker ps
```

### 3. 配置后端

`web/config.ini` 默认配置如下：

```ini
[server]
host = 0.0.0.0
port = 5006
cors_origins = *
max_upload_size = 104857600

[paths]
upload_dir = FastAPI/uploads

[codefender]
api_base = http://127.0.0.1:8001
scan_endpoint = /scan/file
predict_endpoint = /predict
timeout = 300
threshold = 0.5
host_path_prefix =
container_path_prefix =

[docker]
container_name = codefender-api
container_upload_dir = /tmp/codefender_uploads
```

配置中的相对路径以 `web/` 为基准，默认上传目录是 `web/FastAPI/uploads`。前端地址配置保留在 `web/Vue/public/config.ini`，供浏览器通过 `/config.ini` 加载。

默认模式不需要给 Docker 挂载目录。后端会把上传样本复制到模型容器的 `container_upload_dir`，再调用 `/scan/file` 检测。

如果你希望使用目录挂载方式，也可以这样启动 Docker：

```powershell
docker run -d --name codefender-api -p 8001:8000 `
  -v "C:\zjp\github\NKAMG-AIDefender\web\FastAPI\uploads:/samples/uploads" `
  peng233/codefender:v2
```

同时把 `web/config.ini` 改成：

```ini
[codefender]
host_path_prefix = C:\zjp\github\NKAMG-AIDefender\web\FastAPI\uploads
container_path_prefix = /samples/uploads
```

### 4. 启动后端

```powershell
cd C:\zjp\github\NKAMG-AIDefender\web\FastAPI
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

默认后端地址：

```text
http://127.0.0.1:5006
```

验证后端：

```powershell
curl http://127.0.0.1:5006/health
curl http://127.0.0.1:5006/models
```

### 5. 启动前端

```powershell
cd C:\zjp\github\NKAMG-AIDefender\web\Vue
npm install
npm run dev
```

默认前端地址：

```text
http://127.0.0.1:9528
```

打开浏览器访问该地址，上传 PE 样本即可检测。

## 生产构建

前端构建：

```powershell
cd C:\zjp\github\NKAMG-AIDefender\web\Vue
npm run build
```

构建产物在：

```text
web/Vue/dist
```

后端可使用 `uvicorn` 启动：

```powershell
cd C:\zjp\github\NKAMG-AIDefender\web\FastAPI
uvicorn main:app --host 0.0.0.0 --port 5006
```

## 常用接口

- `GET /health`：后端健康检查
- `GET /models`：返回 33 个模型名称
- `POST /detect`：上传 PE 文件并返回基础信息、PE 结构信息和模型检测结果

## 排查问题

### 前端能上传，但模型检测没有结果

优先检查模型 Docker 是否正常：

```powershell
docker ps
curl http://127.0.0.1:8001/health
```

再确认 `web/config.ini` 的容器名是否正确：

```ini
[docker]
container_name = codefender-api
```

如果 `docker ps` 显示的容器名不是 `codefender-api`，把 `container_name` 改成实际名称，然后重启后端。

### 上传后提示不是 PE 样本

后端会校验 `MZ` 头、`PE\0\0` 签名和可选头结构。普通文本、压缩包、PDF、损坏样本会被拒绝。

### Docker 端口冲突

如果本机 8001 已被占用，可以换一个宿主机端口：

```powershell
docker run -d --name codefender-api -p 8011:8000 peng233/codefender:v2
```

同时修改：

```ini
[codefender]
api_base = http://127.0.0.1:8011
```
