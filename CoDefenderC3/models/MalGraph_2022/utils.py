import os
import torch
from torch.utils.data import Dataset
from torch_geometric.data import Data, Batch, DataLoader
import hashlib
import json
from models.MalGraph_2022.Vocabulary import Vocab
from tqdm import tqdm


def calculate_file_hash(file_path):
    """
    计算文件的 SHA256 哈希值
    :param file_path: str 文件路径
    :return: str 文件的 SHA256 哈希值
    """
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def extract_cfg_and_fcg(file_path, vocab_dict):
    """提取函数调用图（FCG）和控制流图（CFG）。

    ⚠ 本函数已**不再依赖 BinaryNinja**：
       PE → ProgramIR（feature_extraction.backend，按 CODEFENDER_DISASM_BACKEND
       选 bn / smda）→ models.MalGraph_2022.graph_from_ir → MalGraph 特征。
       图特征算法见 graph_from_ir.py（与旧 BN 直读实现逐项等价）。

    :param file_path: str PE 文件路径
    :param vocab_dict: dict 外部函数名词表（原地累加）
    :return: dict 包含 function_edges、acfg_list 等；失败返回 None
    """
    try:
        from feature_extraction.backend import build_ir_for_graph
        from models.MalGraph_2022.graph_from_ir import extract_cfg_and_fcg_from_ir

        # 计算文件哈希
        file_hash = calculate_file_hash(file_path)

        ir = build_ir_for_graph(file_path)
        if ir is None:
            raise ValueError(f"无法解析文件：{file_path}")

        results = extract_cfg_and_fcg_from_ir(ir, vocab_dict)
        results["hash"] = file_hash
        return results

    except Exception as e:
        print(f"处理文件时出错：{e}")
        return None


def extract_features_to_jsonl(base_dir, output_dir):
    """
    遍历 PE样本目录，按照所在目录分配标签，将所有提取特征并保存为JSONl文件。
    """
    vocab_dict= {} # 训练集的vocab统计
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    file_counter = 0  # 文件计数器

    with open(os.path.join(output_dir, "features.jsonl"), "w", encoding='utf-8') as jsonl_file:
        for root, _, files in os.walk(base_dir):
            for file in files:
                file_path = os.path.join(root, file)
                file_counter += 1  # 更新计数器
                print(f"[{file_counter}] Processing: {file_path}")
                try:
                    # 提取特征
                    data = extract_cfg_and_fcg(file_path,vocab_dict)
                    if "malicious_unpacked" in file_path:
                        data['label'] = 1
                    else:
                        data['label'] = 0

                    jsonl_file.write(json.dumps(data) + '\n')
                except Exception as e:
                    print(f"Error processing {file_path}: {e}")

    save_vocab_from_train(vocab_dict,output_dir)
    print(f"Total files processed: {file_counter}")


def save_vocab_from_train(vocab_dict, output_dir):
    output_file_path = os.path.join(output_dir, "train_external_function_name_vocab.jsonl")
    with open(output_file_path, "w", encoding='utf-8') as jsonl_file:
        for f_name, count in tqdm(vocab_dict.items(), desc="Writing to JSONL"):
            json_line = json.dumps({"f_name": f_name, "count": count}, ensure_ascii=False)
            jsonl_file.write(json_line + '\n')

    print(f"Successfully wrote to {output_file_path}")

def parse_json_list_2_pyg_object(jsonl_file, output_dir, vocab):
    """将 JSONL 转换为 PyTorch Geometric 的 .pt 文件"""
    index = 0
    with open(jsonl_file, "r", encoding="utf-8") as file:
        for item in tqdm(file, desc="Processing JSONL to PyG Object"):
            item = json.loads(item)
            item_hash = item['hash']
            label = item['label']  # 获取标签

            # 处理 ACFG 列表
            acfg_list = []
            for one_acfg in item['acfg_list']:
                block_features = one_acfg['block_features']
                block_edges = one_acfg['block_edges']
                one_acfg_data = Data(
                    x=torch.tensor(block_features, dtype=torch.float),
                    edge_index=torch.tensor(block_edges, dtype=torch.long)
                )
                acfg_list.append(one_acfg_data)

            # 处理函数信息
            item_function_names = item['function_names']
            item_function_edges = item['function_edges']

            local_function_name_list = item_function_names[:len(acfg_list)]
            assert len(acfg_list) == len(
                local_function_name_list
            ), "The length of ACFG_List should be equal to the length of Local_Function_List"
            external_function_name_list = item_function_names[len(acfg_list):]

            # 将外部函数名映射到索引
            external_function_index_list = [vocab[f_name] for f_name in external_function_name_list]

            # 增加索引并保存为 .pt 文件
            index += 1
            torch.save(
                Data(
                    hash=item_hash,
                    local_acfgs=acfg_list,
                    external_list=external_function_index_list,
                    function_edges=item_function_edges,
                    targets=label
                ),
                os.path.join(output_dir, f"{index}.pt")
            )

class MalwareDataset(Dataset):
    def __init__(self, root):
        """
        初始化数据集
        :param root: str 数据存放目录
        """
        self.root = root
        self.files = [f for f in os.listdir(root) if f.endswith('.pt')]

    def __len__(self):
        """
        数据集的大小
        """
        return len(self.files)

    def __getitem__(self, idx):
        """
        加载单个样本
        :param idx: int 样本索引
        :return: PyG 的 Data 对象
        """
        file_path = os.path.join(self.root, self.files[idx])
        data = torch.load(file_path)

        # 确保加载的是 PyG 的 Data 对象
        assert isinstance(data, Data), "Loaded object is not a PyG Data instance"
        return data



def train_hgnn_model(train_graphs, model, optimizer, loss_fn, device):
    """
    训练 Hierarchical Graph Neural Network 模型。
    """
    model.train()
    data_loader = DataLoader(train_graphs, batch_size=16, shuffle=True)

    for batch in data_loader:
        batch = batch.to(device)
        optimizer.zero_grad()
        output = model(batch)
        loss = loss_fn(output, batch.y)
        loss.backward()
        optimizer.step()


def predict_hgnn_model(test_graphs, model, device):
    """
    使用 Hierarchical Graph Neural Network 模型进行预测。
    """
    model.eval()
    data_loader = DataLoader(test_graphs, batch_size=16, shuffle=False)

    predictions = []
    with torch.no_grad():
        for batch in data_loader:
            batch = batch.to(device)
            output = model(batch)
            predictions.append(output)
    return torch.cat(predictions)


def main():
    # 输入和输出路径
    base_dir = r"E:/Experimental data/dr_data"
    output_jsonl = "./output/features.jsonl"
    output_pt_dir = "./output/pt_files"

    # 参数配置
    label_benign = 0
    label_malicious = 1

    # 确保输出目录存在
    os.makedirs(output_pt_dir, exist_ok=True)


    extract_features_to_jsonl(base_dir, './output')
    print(f"JSONL file saved to {output_jsonl}")
    max_vocab_size = 1000
    vocab = Vocab(freq_file="./output/train_external_function_name_vocab.jsonl",
                  max_vocab_size=max_vocab_size)
    # 转换 JSONL 文件为 .pt 文件
    parse_json_list_2_pyg_object(output_jsonl, output_pt_dir, vocab)
    print(f"PyTorch .pt files saved to {output_pt_dir}")

if __name__ == "__main__":
    ben = r"E:\Experimental data\dr_data\benign_unpacked\benign\0a0af2a5a163108be41c32656b31f0d0ca53a4b1355ddfa491b7bb0056e477b5"
    mal = r"E:\Experimental data\dr_data\malicious_unpacked\2021\Adware\0a5835bf0ec2ba8256efbb35f8b27559"
    # extract_cfg_and_fcg(mal, {})
    main()