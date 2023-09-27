import json
import itertools
from all_utils import compute_kernel_bias, sents_to_vecs, transform_and_normalize, normalize, load_whiten
from transformers import RobertaTokenizer, RobertaModel
import torch
import os
import numpy as np
import csv

os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'

DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
def load_data():
    with open('./T1053.005.txt', 'r') as f:
        json_list = json.loads(f.read())
        field_key_set = set()
        for i in json_list:
            for j in i:
                for k in j['Slot']:
                    field_key_set.update(k.keys())
    return list(itertools.combinations(field_key_set, 2))

sent_tuple = load_data()
# sent_tuple = [('Persistence Type', 'Task Scheduler'), ('Persistence Type', 'Script Language'), ('Persistence Type', 'Task Scheduling'), ('Persistence Type', 'Scripting Language'), ('Persistence Type', 'Persistence Type')]
# print(sent_tuple)
a_sents = [item[0] for item in sent_tuple]
b_sents = [item[1] for item in sent_tuple]

# 加载模型和分词器
tokenizer = RobertaTokenizer.from_pretrained("./SecureBERT/")
model = RobertaModel.from_pretrained("./SecureBERT/")
model.eval()
N_COMPONENTS = 256
MAX_LENGTH = 64
a_vecs = sents_to_vecs(a_sents, tokenizer, model, 'first_last_avg', MAX_LENGTH)
b_vecs = sents_to_vecs(b_sents, tokenizer, model, 'first_last_avg', MAX_LENGTH)

# kernel, bias = compute_kernel_bias([a_vecs, b_vecs], n_components=N_COMPONENTS)
# kernel.dump('kernel_data')
# bias.dump('bias_data')
# kernel, bias = load_whiten('bert-large-nli-mean-tokens-first_last_avg-whiten(NLI).pkl')
# bias = bias[:, :768]
# print(bias.shape)
# whilening_a_vecs = transform_and_normalize(a_vecs, kernel, bias)
# whilening_b_vecs = transform_and_normalize(b_vecs, kernel, bias)
normalized_a_vecs = normalize(a_vecs)
normalized_b_vecs = normalize(b_vecs)
result = []
for a_sent, b_sent, a_vec, b_vec in zip(a_sents, b_sents, normalized_a_vecs, normalized_b_vecs):
    cos_similarity = np.dot(a_vec, b_vec)
    print(a_sent, b_sent, cos_similarity)
    result.append((a_sent, b_sent, cos_similarity))
result.sort(key=lambda x: x[2])
print(result)
with open('result.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    for line in result:
        writer.writerow(line)
