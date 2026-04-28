from seal import *
import numpy as np

import torch
import torchvision
import torchvision.transforms as transforms
# 显示部分数据
import matplotlib.pyplot as plt
import time
from typing import List, Tuple
import io


# 数据预处理（标准化）
transform = transforms.Compose([
    transforms.ToTensor(),  # 将图片转为 Tensor
    #transforms.Normalize((0.5, 0.5, 0.5), (0.5, 0.5, 0.5))  # 标准化
])

# 下载与加载测试数据
testset = torchvision.datasets.CIFAR10(
    root='./data',
    train=False,
    download=True,
    transform= transform
)

testloader = torch.utils.data.DataLoader(
    testset,
    batch_size=100,
    shuffle=False
)

# 随机获取一批数据
dataiter = iter(testloader)
images, labels = next(dataiter)

#numpy数组
transfer_data = torchvision.utils.make_grid(images[45]).numpy()
# print(transfer_data.dtype)
# exit()
arr_rgb = np.transpose(transfer_data, (1, 2, 0))

arr_gray = (
    0.299 * arr_rgb[:, :, 0] +
    0.587 * arr_rgb[:, :, 1] +
    0.114 * arr_rgb[:, :, 2]
)

print(arr_gray.shape)  # (H, W)
# print
#plt.imsave('output.png', arr_rgb)
arr_gray = arr_gray.astype(np.float64)
transfer_data = transfer_data.astype(np.float64)
np.save("data_45.npy", transfer_data)
exit()
