import argparse
import json
import re
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from PIL import Image


CIFAR10_LABELS = [
    "airplane",
    "automobile",
    "bird",
    "cat",
    "deer",
    "dog",
    "frog",
    "horse",
    "ship",
    "truck",
]


def conv3x3(in_planes, out_planes, stride=1):
    return nn.Conv2d(
        in_planes,
        out_planes,
        kernel_size=3,
        stride=stride,
        padding=1,
        bias=False,
    )


class BasicBlock(nn.Module):
    expansion = 1

    def __init__(self, in_planes, planes, stride=1):
        super().__init__()
        self.conv1 = conv3x3(in_planes, planes, stride)
        self.bn1 = nn.BatchNorm2d(planes)
        self.relu = nn.ReLU(inplace=True)
        self.conv2 = conv3x3(planes, planes)
        self.bn2 = nn.BatchNorm2d(planes)

        self.downsample = None
        if stride != 1 or in_planes != planes:
            self.downsample = nn.Sequential(
                nn.Conv2d(in_planes, planes, kernel_size=1, stride=stride, bias=False),
                nn.BatchNorm2d(planes),
            )

    def forward(self, x):
        identity = x

        out = self.conv1(x)
        out = self.bn1(out)
        out = self.relu(out)

        out = self.conv2(out)
        out = self.bn2(out)

        if self.downsample is not None:
            identity = self.downsample(x)

        out = out + identity
        out = self.relu(out)
        return out


class CifarResNet18(nn.Module):
    def __init__(self, num_classes=10):
        super().__init__()
        self.in_planes = 64
        self.conv1 = conv3x3(3, 64)
        self.bn1 = nn.BatchNorm2d(64)
        self.relu = nn.ReLU(inplace=True)
        self.layer1 = self._make_layer(64, 2, stride=1)
        self.layer2 = self._make_layer(128, 2, stride=2)
        self.layer3 = self._make_layer(256, 2, stride=2)
        self.layer4 = self._make_layer(512, 2, stride=2)
        self.avgpool = nn.AdaptiveAvgPool2d((1, 1))
        self.fc = nn.Linear(512, num_classes)

    def _make_layer(self, planes, blocks, stride):
        layers = [BasicBlock(self.in_planes, planes, stride)]
        self.in_planes = planes
        for _ in range(1, blocks):
            layers.append(BasicBlock(self.in_planes, planes))
        return nn.Sequential(*layers)

    def forward_features(self, x):
        x = self.conv1(x)
        x = self.bn1(x)
        x = self.relu(x)
        x = self.layer1(x)
        x = self.layer2(x)
        x = self.layer3(x)
        x = self.layer4(x)
        x = self.avgpool(x)
        return torch.flatten(x, 1)

    def forward(self, x):
        return self.fc(self.forward_features(x))


def find_checkpoint(model_dir):
    model_path = Path(model_dir)
    if model_path.is_file():
        return model_path

    for name in ["pytorch_model.bin", "model.pth", "checkpoint.pth"]:
        candidate = model_path / name
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"No checkpoint found under {model_path}")


def load_config(model_dir):
    config_path = Path(model_dir) / "config.json"
    if not config_path.exists():
        return {
            "input_size": [3, 32, 32],
            "mean": [0.4914, 0.4822, 0.4465],
            "std": [0.2023, 0.1994, 0.2010],
        }
    with config_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_state_dict(checkpoint):
    state = torch.load(checkpoint, map_location="cpu")
    state_dict = state.get("state_dict", state.get("model", state))
    return {key.removeprefix("module."): value for key, value in state_dict.items()}


def load_model(model_dir):
    checkpoint = find_checkpoint(model_dir)
    model = CifarResNet18(num_classes=10)
    missing, unexpected = model.load_state_dict(load_state_dict(checkpoint), strict=False)
    if missing or unexpected:
        raise RuntimeError(f"Checkpoint mismatch. missing={missing}, unexpected={unexpected}")
    model.eval()
    return model, checkpoint


def make_input_tensor(image_path, config):
    input_size = config.get("input_size", [3, 32, 32])
    height, width = int(input_size[1]), int(input_size[2])
    mean = np.asarray(config.get("mean", [0.4914, 0.4822, 0.4465]), dtype=np.float32)
    std = np.asarray(config.get("std", [0.2023, 0.1994, 0.2010]), dtype=np.float32)

    if image_path is None:
        grid = np.linspace(0.0, 1.0, height * width, dtype=np.float32).reshape(height, width)
        image = np.stack([grid, np.flipud(grid), np.fliplr(grid)], axis=-1)
    else:
        image = Image.open(image_path).convert("RGB").resize((width, height), Image.BILINEAR)
        image = np.asarray(image, dtype=np.float32) / 255.0

    image = (image - mean) / std
    image = np.transpose(image, (2, 0, 1))
    return torch.from_numpy(image).unsqueeze(0)


def list_labeled_images(image_dir, limit):
    pattern = re.compile(r"data_(\d+)_label_(\d+)\.png$")
    items = []
    for path in Path(image_dir).glob("*.png"):
        match = pattern.match(path.name)
        if match is None:
            continue
        items.append((int(match.group(1)), path, int(match.group(2))))

    items.sort(key=lambda item: item[0])
    if limit is not None:
        items = items[:limit]
    if not items:
        raise FileNotFoundError(f"No labeled PNG files found under {image_dir}")
    return items


def main():
    parser = argparse.ArgumentParser(
        description="Export pretrained ResNet18-CIFAR10 features and head weights for CKKS."
    )
    parser.add_argument("--model-dir", default="resnet18_cifar10")
    parser.add_argument("--image", default=None, help="Optional input image path.")
    parser.add_argument("--image-dir", default="images_png", help="Directory of data_<id>_label_<y>.png files.")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--output-dir", default=".")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    model, checkpoint = load_model(args.model_dir)
    config = load_config(args.model_dir)

    if args.image is not None:
        labeled_images = [(0, Path(args.image), -1)]
    else:
        labeled_images = list_labeled_images(args.image_dir, args.limit)

    with torch.no_grad():
        features = []
        logits_list = []
        labels = []
        correct = 0
        labeled_count = 0
        for _, image_path, label in labeled_images:
            x = make_input_tensor(image_path, config)
            feature_tensor = model.forward_features(x)
            logits_tensor = model.fc(feature_tensor).squeeze(0)
            pred = int(torch.argmax(logits_tensor).item())

            features.append(feature_tensor.squeeze(0).double().cpu().numpy())
            logits_list.append(logits_tensor.double().cpu().numpy())
            labels.append(label)
            if label >= 0:
                labeled_count += 1
                correct += int(pred == label)

    features = np.stack(features).astype(np.float64)
    logits = np.stack(logits_list).astype(np.float64)
    labels = np.asarray(labels, dtype=np.int64)

    weight = model.fc.weight.detach().cpu().double().numpy()
    bias = model.fc.bias.detach().cpu().double().numpy()

    np.save(output_dir / "data.npy", features)
    np.save(output_dir / "labels.npy", labels)
    np.save(output_dir / "linear_weights.npy", weight)
    np.save(output_dir / "linear_bias.npy", bias)
    np.save(output_dir / "resnet18_logits.npy", logits)

    print(f"Loaded checkpoint: {checkpoint}")
    print(f"Saved {output_dir / 'data.npy'} {features.shape} {features.dtype}")
    print(f"Saved {output_dir / 'labels.npy'} {labels.shape} {labels.dtype}")
    print(f"Saved {output_dir / 'linear_weights.npy'} {weight.shape} {weight.dtype}")
    print(f"Saved {output_dir / 'linear_bias.npy'} {bias.shape} {bias.dtype}")
    print(f"Saved {output_dir / 'resnet18_logits.npy'} {logits.shape} {logits.dtype}")
    if labeled_count > 0:
        accuracy = correct / labeled_count
        print(f"Plain ResNet18 accuracy: {correct}/{labeled_count} = {accuracy:.6f}")


if __name__ == "__main__":
    main()
