from sentence_transformers import SentenceTransformer, SentencesDataset
import csv
from tqdm import tqdm
sentences = ["Task Type", "Job Type"]

model = SentenceTransformer('./ATTACK-BERT')
embeddings = model.encode(sentences)

from sklearn.metrics.pairwise import cosine_similarity
print(cosine_similarity([embeddings[0]], [embeddings[1]]))

import itertools
import json
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
result = []
for sent in tqdm(sent_tuple):
    embeddings = model.encode(sent)
    result.append((sent[0], sent[1], float(cosine_similarity([embeddings[0]], [embeddings[1]]))))
result.sort(key=lambda x: x[2])
with open('attck_bert_result.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    for line in result:
        writer.writerow(line)