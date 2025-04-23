# from ast import Tuple
# from re import T
# import numpy as np
# import random
# import copy
# import os
# import time

import torch
import torch.nn as nn
import torch.nn.functional as F
import torchvision
import torchvision.models as models
from torchvision.datasets import ImageFolder
from torchvision.utils import make_grid
import torchvision.transforms as transforms
from torch.utils.data import Dataset, DataLoader, ConcatDataset
from PIL import Image
# from sklearn.metrics import roc_auc_score
# from sklearn.metrics import f1_score
# from sklearn.preprocessing import MultiLabelBinarizer

import torch
import torchvision
import torchvision.transforms as transforms
import torch.nn as nn
from PIL import Image


#MODEL = r'C:\Users\Jason\Desktop\INDUSTRY_PROJECT\Mid_term_report_performance\Brain_Tumor_Classifier\Brain_Tumor_Classifier\model\densenet_model.pth'
MODEL = r'./model/densenet_model.pth'

def make_pred(image_to_analyze):
    class1 = {0: 'glioma_tumor', 1: 'meningioma_tumor', 
              2: 'normal', 3: 'pituitary_tumor'}

    transforming_img = transforms.Compose([
        transforms.Resize((224, 224)),
        transforms.ToTensor(),
    ])

    # Load the model
    model = torchvision.models.densenet161(pretrained=True)
    in_features = model.classifier.in_features
    model.classifier = nn.Linear(in_features, len(class1))
    model.load_state_dict(torch.load(MODEL, map_location="cpu"))
    device = torch.device("cpu")
    model = model.to(device)
    model.eval()

    #print("Using densenet model for Brain Tumor Classification")

    # Specify the image path here
    #image_path = image_to_analyze
    #image = Image.open(image_to_analyze)
    image = transforming_img(image_to_analyze).unsqueeze(0).to(device)  # Add batch dimension
    # Make prediction
    with torch.no_grad():
        output = model(image)
        probabilities = nn.Softmax(dim=1)(output).cpu().numpy()[0]

    # Get the predicted class and its confidence score
    predicted_class = class1[probabilities.argmax()]

    analysis = f'AI prediction: {predicted_class}' + '\n' + 'Details:' + '\n'
    for idx, score in enumerate(probabilities):
        analysis += f"{class1[idx]}: {score:.4f} \n"
   # print(f"analysis: {analysis}")
    return analysis

#print(make_pred(r'C:\Users\Jason\Desktop\True_Images\normal.jpg'))
#print(make_pred('extracted_image.jpg'))
