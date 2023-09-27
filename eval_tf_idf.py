from collections import defaultdict
from mitreattack.stix20 import MitreAttackData
import numpy as np

from utils import *

def normalize(vecs):
    """标准化
    """
    return vecs / (vecs**2).sum(axis=1, keepdims=True)**0.5

# TODO: 用函数代替
mitre_attack_data = MitreAttackData("./cti/enterprise-attack/enterprise-attack.json")
techniques_used_by_groups = mitre_attack_data.get_all_techniques_used_by_all_groups()
techniques = [mitre_attack_data.get_attack_id(stix_object.id) for stix_object in mitre_attack_data.get_techniques()]
group2techniques = defaultdict(set)
for group_stix_id in techniques_used_by_groups:
    group_attck_id = mitre_attack_data.get_attack_id(group_stix_id)
    for technique_stix in techniques_used_by_groups[group_stix_id]:
        technique_attck_id = mitre_attack_data.get_attack_id(technique_stix['object'].id)
        group2techniques[group_attck_id].add(technique_attck_id)

dim = len(techniques)
technique_attck_id_to_index = {}
for index, technique in enumerate(techniques):
    technique_attck_id_to_index[technique] = index
groups_num = len(group2techniques.keys())
technique_tf = np.zeros((groups_num, dim))
technique_idf = np.zeros(dim)
technique_df = np.zeros(dim)
for technique in techniques:
    num = 0
    for technique_set in group2techniques.values():
        if technique in technique_set:
            num += 1
    technique_df[technique_attck_id_to_index[technique]] = num
technique_idf = np.log(groups_num/(technique_df+1))
for index, technique_set in enumerate(group2techniques.values()):
    n = len(technique_set)
    for technique in technique_set:
       technique_tf[index][technique_attck_id_to_index[technique]] = 1/n
tf_idf = np.multiply(technique_tf , technique_idf)
# 正则化
tf_idf = normalize(tf_idf)

# 输入安全事件
def attribute(event_techniques):
    vector = np.zeros((1, dim))
    for technique in event_techniques:
        vector[0][technique_attck_id_to_index[technique]] = 1
    vector = normalize(vector)
    attribution_result = []
    # 输出概率分布
    cos_similarity_vector = np.dot(vector, tf_idf.T)
    cos_similarity_vector = softmax(cos_similarity_vector)[0]
    for index, similarity in enumerate(cos_similarity_vector):
        attribution_result.append((similarity, list(GROUP_ATTCK_ID_TO_INDEX.keys())[index]))
    attribution_result.sort(key=lambda x: x[0], reverse=True)
    for index, result in enumerate(attribution_result):
        print(f'Top: {index+1}, Probability: {round(result[0]*100, 2)}%, Group: {result[1]}')
    # # 输出相似度
    # for index, row in enumerate(tf_idf):
    #     cos_similarity = np.dot(vector, row)
    #     attribution_result.append((cos_similarity[0], list(group2techniques.keys())[index]))
    # attribution_result.sort(key=lambda x: x[0], reverse=True)
    # for index, result in enumerate(attribution_result):
    #     print(index+1, result)
attribute(Turla_1_techniques)