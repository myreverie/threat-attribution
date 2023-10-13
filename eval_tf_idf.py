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

def attribute(tf_idf_matrix, event_techniques, ground_truth=None):
    """使用计算好的TF-IDF矩阵进行归因分析"""
    vector = np.zeros((1, TECHNIQUES_NUM))
    for technique in event_techniques:
        vector[0][TECHNIQUE_ATTCK_ID_TO_INDEX[technique]] = 1
    vector = normalize(vector)
    attribution_result = []

    # 输出概率分布
    cos_similarity_vector = np.dot(vector, tf_idf_matrix.T)
    # cos_similarity_vector = softmax(cos_similarity_vector)[0]
    cos_similarity_vector = simple_normalize(cos_similarity_vector)[0]
    for index, similarity in enumerate(cos_similarity_vector):
        attribution_result.append((similarity, list(GROUP_ATTCK_ID_TO_INDEX.keys())[index]))
    attribution_result.sort(key=lambda x: x[0], reverse=True)
    for index, result in enumerate(attribution_result):
        print(f'Top: {index+1}, Probability: {round(result[0]*100, 2)}%, Group: {result[1]}')

    # # 输出安全事件技术个数
    # print(f'安全事件技术个数：{len(event_techniques)}')

    # # 输出安全事件被广泛使用的技术占比
    # often_used_TTP_number = 0
    # for technique in event_techniques:
    #     if is_often_used_TTP(technique) is True:
    #         often_used_TTP_number += 1
    # print(f'被广泛使用的技术个数：{often_used_TTP_number}')
    # print(f'被广泛使用的技术占比：{round((often_used_TTP_number/len(event_techniques))*100, 2)}%')


    # 根据答案计算排名指标
    if ground_truth is not None:
        # 计算ATT&CK中该组织技术的收录情况
        group2techniques = get_group2techniques_data()
        print(f'ATT&CK中收录的{ground_truth}组织的技术共有{len(group2techniques[ground_truth])}个')
        # 分析重叠情况
        intersection_technique = event_techniques.intersection(set(group2techniques[ground_truth]))
        often_used_TTP_number = 0
        for technique in intersection_technique:
            if is_often_used_TTP(technique) is True:
                often_used_TTP_number += 1
        print(f'ATT&CK收录的技术与本报告发现的技术交集元素数为{len(intersection_technique)}个，其中被广泛使用的技术有{often_used_TTP_number}个')
        loss = 0
        for index, result in enumerate(attribution_result):
            if result[1] != ground_truth:
                loss += result[0]
            else:
                print(f'Top: {index+1}, Probability: {round(result[0]*100, 2)}%, Group: {result[1]}')
                print(f'相似度排名指标得分为：{round(1-loss, 2)}')
                break

if __name__ == '__main__':
    tf_idf_matrix = calc_tf_idf_matrix()
    attribute(tf_idf_matrix, G0094_2, 'G0094')