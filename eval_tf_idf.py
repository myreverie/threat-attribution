import numpy as np

from utils import *

def calc_tf_idf_matrix():
    """计算TF-IDF矩阵"""
    group2techniques = get_group2techniques_data()
    techniques = get_techniques()
    technique_tf = np.zeros((GROUPS_NUM, TECHNIQUES_NUM))
    technique_idf = np.zeros(TECHNIQUES_NUM)
    technique_df = np.zeros(TECHNIQUES_NUM)
    for technique in techniques:
        num = 0
        for technique_set in group2techniques.values():
            if technique in technique_set:
                num += 1
        technique_df[TECHNIQUE_ATTCK_ID_TO_INDEX[technique]] = num
    technique_idf = np.log(GROUPS_NUM/(technique_df+1))
    for index, technique_set in enumerate(group2techniques.values()):
        n = len(technique_set)
        for technique in technique_set:
            technique_tf[index][TECHNIQUE_ATTCK_ID_TO_INDEX[technique]] = 1/n
    tf_idf = np.multiply(technique_tf , technique_idf)
    # 正则化
    tf_idf = normalize(tf_idf)
    return tf_idf

def attribute(tf_idf_matrix, event_techniques):
    """使用计算好的TF-IDF矩阵进行归因分析"""
    vector = np.zeros((1, TECHNIQUES_NUM))
    for technique in event_techniques:
        vector[0][TECHNIQUE_ATTCK_ID_TO_INDEX[technique]] = 1
    vector = normalize(vector)
    attribution_result = []

    # 输出概率分布
    cos_similarity_vector = np.dot(vector, tf_idf_matrix.T)
    cos_similarity_vector = softmax(cos_similarity_vector)[0]
    for index, similarity in enumerate(cos_similarity_vector):
        attribution_result.append((similarity, list(GROUP_ATTCK_ID_TO_INDEX.keys())[index]))
    attribution_result.sort(key=lambda x: x[0], reverse=True)
    for index, result in enumerate(attribution_result):
        print(f'Top: {index+1}, Probability: {round(result[0]*100, 2)}%, Group: {result[1]}')


if __name__ == '__main__':
    tf_idf_matrix = calc_tf_idf_matrix()
    attribute(tf_idf_matrix, APT28_1_techniques)