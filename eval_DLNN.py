import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset, random_split

from utils import *

from random import sample

DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

# 定义神经网络
class SingleLayerNet(nn.Module):
    def __init__(self, input_size, num_classes):
        super(SingleLayerNet, self).__init__()
        self.fc = nn.Linear(input_size, num_classes)

    def forward(self, x):
        x = self.fc(x)
        return x


class SampledEventsDataset(Dataset):
    def __init__(self, group_with_techniques_data, average_technique_num=10, sample_times=50, sample_rate=0.7):
        self.data = group_with_techniques_data
        self.events = []

        for group, techniques in group_with_techniques_data.items():
            for _ in range(sample_times):
                max_technique_num = len(list(techniques))
                sample_num = max_technique_num if max_technique_num < average_technique_num else average_technique_num
                technique_vector = torch.zeros(TECHNIQUES_NUM)
                group_vector = torch.zeros(GROUPS_NUM)
                for technique in sample(list(techniques), sample_num):
                    technique_vector[TECHNIQUE_ATTCK_ID_TO_INDEX[technique]] = 1.0
                group_vector[GROUP_ATTCK_ID_TO_INDEX[group]] = 1.0
                self.events.append((technique_vector, group_vector))

    def __len__(self):
        return len(self.events)

    def __getitem__(self, idx):
        return self.events[idx]

def load_data(group2techniques, batch_size, train_ratio=0.8):
    """创建DataLoader"""
    # 加载数据
    dataset = SampledEventsDataset(group2techniques)

    # 确定划分比例
    test_ratio = 1 - train_ratio # 测试集比例

    # 计算划分的样本数量
    total_samples = len(dataset)
    train_size = int(train_ratio * total_samples)
    test_size = total_samples - train_size

    # 划分数据集
    train_dataset, test_dataset = random_split(dataset, [train_size, test_size])

    # 使用 DataLoader 加载数据
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
    print(len(train_dataset))

    return train_loader, test_loader

def train(model, train_loader, learning_rate, epochs):
    """模型训练"""
    # 定义损失函数和优化器
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    for epoch in range(epochs):
        total_loss = 0
        for technique_vector, group_vector in train_loader:
            model.to(DEVICE)
            technique_vector.to(DEVICE)
            group_vector.to(DEVICE)
            # 正向传播
            output = model(technique_vector)
            loss = criterion(output, group_vector)

            # 反向传播和优化
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            total_loss += loss.item()

        print(f'Epoch [{epoch+1}/{epochs}], Loss: {total_loss/len(train_loader)}')
    print('训练完成!')

def eval(model, test_loader):
    """在测试集上评估模型"""
    model.eval()

    correct = 0
    total = 0
    with torch.no_grad():
        for technique_vector, group_vector in test_loader:
            model.to(DEVICE)
            technique_vector.to(DEVICE)
            group_vector.to(DEVICE)
            output = model(technique_vector)
            _, predict = torch.max(output.data, 1)
            _, label = torch.max(group_vector.data, 1)
            total += label.size(0)
            correct += (predict == label).sum().item()
    print(f'模型在测试集上的准确率为: {100 * correct / total}%')

def save_model(model, model_name):
    """保存训练好的模型"""
    torch.save(model, f'./model/{model_name}.pth')

def load_model(model_name):
    """加载训练好的模型"""
    return torch.load(f'./model/{model_name}.pth')

def attribute(model, event_techniques, ground_truth=None):
    """使用训练好的模型进行归因分析"""
    with torch.no_grad():
        technique_vector = torch.zeros(TECHNIQUES_NUM)
        for technique in event_techniques:
            technique_vector[TECHNIQUE_ATTCK_ID_TO_INDEX[technique]] = 1.0
        output = model(technique_vector)
        # predict = simple_normalize(output.unsqueeze(0))[0]
        predict = torch.softmax(output, dim=0)
        attribution_result = []
        for index, similarity in enumerate(predict):
            attribution_result.append((float(similarity), list(GROUP_ATTCK_ID_TO_INDEX.keys())[index]))
        attribution_result.sort(key=lambda x: x[0], reverse=True)
        for index, result in enumerate(attribution_result):
            print(f'Top: {index+1}, Probability: {round(result[0]*100, 2)}%, Group: {result[1]}')
    # 根据答案计算排名指标
    if ground_truth is not None:
        loss = 0
        for index, result in enumerate(attribution_result):
            if result[1] != ground_truth:
                loss += result[0]
            else:
                print(f'Top: {index+1}, Probability: {round(result[0]*100, 2)}%, Group: {result[1]}')
                print(f'相似度排名指标得分为：{round(1-loss, 2)}')
                break
def train_and_save():
    group2techniques = get_group2techniques_data()
    # 设置超参数
    input_size = TECHNIQUES_NUM
    output_classes = GROUPS_NUM
    learning_rate = 0.001
    batch_size = 64
    epochs = 10
    # 创建模型
    model = SingleLayerNet(input_size, output_classes)
    # 加载数据
    train_loader, test_loader = load_data(group2techniques, batch_size)

    train(model, train_loader, learning_rate, epochs)
    eval(model, test_loader)
    save_model(model, 'DLNN')

def load_and_attribute(event_techniques, ground_truth=None):
    model = load_model('DLNN')
    attribute(model, event_techniques, ground_truth)

if __name__ == '__main__':
    load_and_attribute(G1005_1, 'G1005')
