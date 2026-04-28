import numpy as np

import torch
import torchvision
import torchvision.transforms as transforms
import matplotlib.pyplot as plt
import time
from typing import List, Tuple
import io
import os

path = os.path.dirname(os.path.abspath(__file__))

transform = transforms.Compose([
    transforms.ToTensor(),  #  Tensor
])

# Download
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


dataiter = iter(testloader)
images, labels = next(dataiter)

for i in range(100):
    transfer_data = torchvision.utils.make_grid(images[i]).numpy()
    transfer_data = transfer_data.astype(np.float64)
    output_filename = path + f"/images/data_{i}.npy"
    np.save(output_filename, transfer_data)


