"""
InceptionV3 for Malware Classification — 2020
基于 Nataraj et al. 2011 的恶意软件可视化方法,
使用 InceptionV3 (Szegedy et al. 2016, CVPR) 预训练模型进行迁移学习

Architecture:
  Input: PE binary → grayscale image → 3-channel repeat → 299×299
  InceptionV3 (ImageNet pretrained)
  - 替换最后 FC 层: fc → Linear(2048, num_classes)
  - 去除 AuxLogits

参考论文:
  Nataraj et al. 2011 "Malware Images: Visualization and Automatic Classification"
  Szegedy et al. 2016 "Rethinking the Inception Architecture for Computer Vision"
"""
import torch
import torch.nn as nn


class InceptionV3Model(nn.Module):
    """
    InceptionV3 迁移学习模型
    加载 ImageNet 预训练权重，替换最后分类层
    """
    def __init__(self, num_classes=2, pretrained=True):
        super(InceptionV3Model, self).__init__()

        try:
            import torchvision.models as models
            if pretrained:
                # 训练路径：确实要 ImageNet 权重做迁移学习起点。
                # ⚠ 这里会联网下载 inception_v3_google-0cc3c7bd.pth（~104MB）。
                #   离线/无 DNS 环境请在训练前把该文件放进
                #   $TORCH_HOME/hub/checkpoints/（默认 ~/.cache/torch/hub/checkpoints/）。
                try:
                    weights = models.Inception_V3_Weights.IMAGENET1K_V1
                    self.inception_v3 = models.inception_v3(weights=weights)
                except AttributeError:
                    self.inception_v3 = models.inception_v3(pretrained=True)
            else:
                # 推理/加载路径（ensemble.py::load 恒传 pretrained=False）：
                # 只要网络结构，不要 ImageNet 权重 —— 构造完紧跟
                # model.load_state_dict(训练权重) 会全量覆盖，
                # 下载既纯属浪费，又会让离线容器直接加载失败。
                # ⚠ 刻意用 weights=None 而不是 pretrained=False：后者自
                #   torchvision 0.13 起已弃用，新版本可能直接移除该关键字。
                try:
                    self.inception_v3 = models.inception_v3(weights=None)
                except TypeError:           # 老 torchvision (<0.13) 无 weights 参数
                    self.inception_v3 = models.inception_v3(pretrained=False)
        except ImportError:
            raise ImportError("InceptionV3Model requires torchvision")

        # 替换最后全连接层
        in_features = self.inception_v3.fc.in_features
        self.inception_v3.fc = nn.Linear(in_features, num_classes)

        # 去除辅助分类器 (可选, 在 run 脚本中控制)
        # self.inception_v3.AuxLogits = None

    def forward(self, x):
        """
        Args:
            x: (B, 1, H, W) grayscale, (B, 3, H, W) color, or flat (B, H*W)
        Returns:
            logits (B, num_classes) or (logits, aux_logits) if training with AuxLogits
        """
        if x.dim() == 2:
            H = int(x.shape[1] ** 0.5)
            x = x.reshape(x.size(0), 1, H, H)
        # 灰度→3通道 (Nataraj-style: repeat grayscale to match ImageNet 3ch input)
        if x.shape[1] == 1:
            x = x.expand(-1, 3, -1, -1)
        # InceptionV3 要求最小 299×299 输入
        if x.shape[2] != 299 or x.shape[3] != 299:
            x = torch.nn.functional.interpolate(x, size=(299, 299), mode='bilinear', align_corners=False)
        return self.inception_v3(x)
