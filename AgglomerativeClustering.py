import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import AgglomerativeClustering
from sklearn.metrics.pairwise import cosine_similarity
import csv

word2id = {}
count = 0
with open('./attck_bert_result.csv', 'r') as f:
    f_reader = csv.reader(f)
    matrix = np.zeros((163, 163))
    for row in f_reader:
        if row[0] not in word2id:
            word2id[row[0]] = count
            count += 1
        if row[1] not in word2id:
            word2id[row[1]] = count
            count += 1
        r, c = (word2id[row[0]], word2id[row[1]]) if word2id[row[0]] < word2id[row[1]] else (word2id[row[1]], word2id[row[0]])
        matrix[r][c] = abs(float(row[2]))

print(matrix[:5, :5])

# 使用AgglomerativeClustering进行聚类
threshold = 0.15  # 设置要聚类的簇的数量
agg_clustering = AgglomerativeClustering(n_clusters=None, distance_threshold=threshold, linkage='complete', affinity='cosine')
agg_clustering.fit(matrix[:-1, :])

cluster = {}
for i, label in enumerate(agg_clustering.labels_):
    if label not in cluster:
        cluster[label] = []
    cluster[label].append(list(word2id.keys())[i])
for i in cluster:
    print(i, cluster[i])