from mitreattack.stix20 import MitreAttackData
from stix2 import Filter, FileSystemSource

from typing import List

from collections import defaultdict

import numpy as np

import re
mitre_attack_data = MitreAttackData("./data/cti/enterprise-attack/enterprise-attack.json")
stix_data = FileSystemSource('./data/cti/enterprise-attack')

def get_group2techniques_data():
    """获取组织到技术的映射"""
    techniques_used_by_groups = mitre_attack_data.get_all_techniques_used_by_all_groups()
    group2techniques = defaultdict(set)
    for group_stix_id in techniques_used_by_groups:
        group_attck_id = mitre_attack_data.get_attack_id(group_stix_id)
        for technique_stix in techniques_used_by_groups[group_stix_id]:
            technique_attck_id = mitre_attack_data.get_attack_id(technique_stix['object'].id)
            group2techniques[group_attck_id].add(technique_attck_id)
    return group2techniques

def get_techniques():
    """获取所有的技术ID"""
    techniques = [mitre_attack_data.get_attack_id(stix_object.id) for stix_object in mitre_attack_data.get_techniques()]
    return techniques


def get_technique_attck_id_to_index(techniques):
    technique_attck_id_to_index = {}
    for index, technique in enumerate(techniques):
        technique_attck_id_to_index[technique] = index
    return technique_attck_id_to_index

def get_group_attck_id_to_index(groups):
    group_attck_id_to_index = {}
    for index, group in enumerate(groups):
        group_attck_id_to_index[group] = index
    return group_attck_id_to_index

def softmax(x):
    max = np.max(x,axis=1,keepdims=True) #returns max of each row and keeps same dims
    e_x = np.exp(x - max) #subtracts each row with its max value
    sum = np.sum(e_x,axis=1,keepdims=True) #returns sum of each row and keeps same dims
    f_x = e_x / sum 
    return f_x

def normalize(vecs):
    """向量标准化
    """
    return vecs / (vecs**2).sum(axis=1, keepdims=True)**0.5

def simple_normalize(vecs):
    """通过除以向量的曼哈顿范数来实现向量标准化
    """
    print(vecs.sum(axis=1, keepdims=True))
    return vecs / vecs.sum(axis=1, keepdims=True)

def get_techniques2frequency():
    """获取技术ID到技术使用频率的映射字典"""
    techniques2frequency = defaultdict(int)
    group2techniques = get_group2techniques_data()
    for technique_set in group2techniques.values():
        for technique in technique_set:
            techniques2frequency[technique] += 1
    return techniques2frequency

def is_often_used_TTP(technique_id):
    """根据预定义的阈值，判断一个技术是否是被广泛使用的技术"""
    OFTEN_USED_THEREHOLD = 6
    techniques2frequency = get_techniques2frequency()
    if techniques2frequency[technique_id] >= OFTEN_USED_THEREHOLD:
        return True
    else:
        return False
def procedure_text_preprocess(text):
    """处理ATT&CK的markdown文本"""
    link_pattern = r'\[(.*?)\]\(.*?\)'
    link_replacement = r'\1'
    code_pattern = r'<code>(.*?)</code>'
    code_replacement = r'\1'
    citation_pattern = r'\(Citation: .*?\)'
    citation_replacement = r''
    backquote_pattern = r'`(.*?)`'
    backquote_replacement = r'\1'

    text = re.sub(link_pattern, link_replacement, text)
    text = re.sub(code_pattern, code_replacement, text)
    text = re.sub(citation_pattern, citation_replacement, text)
    text = re.sub(backquote_pattern, backquote_replacement, text)

    return text

def get_procedure_example_by_technique_object_id(techniques_object_id) -> List:
    """根据技术的stix id，找到所有的程序实例"""
    procedure_example_list = []
    query_results = stix_data.query([
        Filter('target_ref', '=', techniques_object_id),
        Filter('relationship_type', '=', 'uses'),
        Filter('type', '=', 'relationship'),
    ])
    for result in query_results:
        # print('处理前：', result.description)
        processed_description = procedure_text_preprocess(result.description)
        # print('处理后：', processed_description)
        procedure_example_list.append(processed_description)
    return procedure_example_list

def get_procedure_example_by_technique_id(technique_id):
    """根据技术的att&ck id，找到所有的程序实例"""
    technique_object_id = mitre_attack_data.get_object_by_attack_id(technique_id, 'attack-pattern').id
    procedure_example_list = get_procedure_example_by_technique_object_id(technique_object_id)
    return procedure_example_list

TECHNIQUES_NUM = len(get_techniques())
GROUPS_NUM = len(get_group2techniques_data().keys())
TECHNIQUE_ATTCK_ID_TO_INDEX = get_technique_attck_id_to_index(get_techniques())
GROUP_ATTCK_ID_TO_INDEX = get_group_attck_id_to_index(get_group2techniques_data().keys())
G0016_1 = {'T1021.001', 'T1036.005', 'T1078.003', 'T1133', 'T1546.003', 'T1550.001', 'T1003.006', 'T1069.002', 'T1482', 'T1213', 'T1078.004', 'T1555.003', 'T1057', 'T1003.001', 'T1539', 'T1098.001', 'T1595.001', 'T1087.002'}
G0016_2 = {'T1566.003', 'T1204.001', 'T1610', 'T1566.002', 'T1071.001'}
G0094_1 = {'T1546.001', 'T1055', 'T1056.001', 'T1218.005', 'T1505.003', 'T1074.001', 'T1082', 'T1189', 'T1021.001', 'T1562.004', 'T1219', 'T1003', 'T1566.002', 'T1566.001', 'T1059.001', 'T1560', 'T1547', 'T1070.004', 'T1550.002', 'T1040', 'T1573.001', 'T1185', 'T1059.006', 'T1114.003', 'T1547.001', 'T1083', 'T1548.002'}
G0007_1 = {'T1036.003', 'T1074.002', 'T1078', 'T1560.001', 'T1098.002', 'T1110.003', 'T1021.002', 'T1213', 'T1048.002', 'T1030', 'T1036.005', 'T1078.002', 'T1114.002', 'T1505.003', 'T1115', 'T1003.001', 'T1003.003', 'T1036', 'T1005', 'T1039', 'T1190'}
G0016_3 = {'T1059.005', 'T1078', 'T1190', 'T1195.002', 'T1505.003', 'T1199', 'T1595.002'}
G0010_1 = {'T1559', 'T1078', 'T1587.001', 'T1119', 'T1132.002', 'T1564', 'T1036', 'T1027.002', 'T1003', 'T1482', 'T1046', 'T1112', 'T1573.001', 'T1083', 'T1106', 'T1547.006', 'T1074', 'T1132', 'T1071.001', 'T1104', 'T1190', 'T1546.016', 'T1569.002', 'T1573.002', 'T1071', 'T1588', 'T1040', 'T1572', 'T1027', 'T1055.001', 'T1059.001', 'T1584', 'T1560.003', 'T1140', 'T1090.003', 'T1610', 'T1071.003', 'T1056.001', 'T1001', 'T1608', 'T1095', 'T1135', 'T1570', 'T1071.004', 'T1001.003', 'T1574.002', 'T1573', 'T1014'}
G0094_2 = {'T1027', 'T1059.001', 'T1140', 'T1585.001', 'T1218.010', 'T1056.001', 'T1083', 'T1113', 'T1587.001', 'T1025', 'T1585.002', 'T1001', 'T1082', 'T1583', 'T1059.007', 'T1041', 'T1560', 'T1071.001', 'T1566.001', 'T1134', 'T1112', 'T1547.001', 'T1598', 'T1005', 'T1070.004'}
G0032_1 = {'T1134.002', 'T1016', 'T1587.001', 'T1573.001', 'T1608.001', 'T1106', 'T1566.003', 'T1071.001', 'T1007', 'T1593.001', 'T1049', 'T1012', 'T1562.004', 'T1140', 'T1053', 'T1135', 'T1566.002', 'T1204.002', 'T1070.004', 'T1070.006', 'T1622', 'T1018', 'T1497.003', 'T1027.009', 'T1202', 'T1574.002', 'T1057', 'T1047', 'T1027.007', 'T1027.002', 'T1041', 'T1585.003', 'T1055', 'T1129', 'T1480', 'T1083', 'T1584.004', 'T1132.001', 'T1620', 'T1585.001', 'T1562.003'}
G0038_1 = {'T1016', 'T1057', 'T1140', 'T1518.001', 'T1005', 'T1134', 'T1204.002', 'T1090', 'T1588.003', 'T1583.003', 'T1047', 'T1112', 'T1007', 'T1218.011', 'T1562.001', 'T1587.001', 'T1620', 'T1583.001', 'T1106', 'T1480.001', 'T1027', 'T1041', 'T1518', 'T1573.001', 'T1546.003', 'T1059.003', 'T1033', 'T1082', 'T1012', 'T1071.001', 'T1070.004'}
G0049_1 = {'T1041', 'T1608.001', 'T1087.001', 'T1082', 'T1562', 'T1555.004', 'T1053.005', 'T1555.003', 'T1566.001', 'T1584.004', 'T1059.003', 'T1027.009', 'T1573.002', 'T1608.002', 'T1070.009', 'T1059.005', 'T1027.002', 'T1033', 'T1001', 'T1553', 'T1132.001', 'T1059.001', 'T1573.001', 'T1587.001', 'T1140', 'T1105', 'T1106', 'T1071.001', 'T1036.005', 'T1083', 'T1036.004', 'T1102.002', 'T1217'}
G0059_1 = {'T1588.002', 'T1543.003', 'T1555.003', 'T1078.003', 'T1569.002', 'T1027', 'T1587.001', 'T1140', 'T1001', 'T1190', 'T1018', 'T1059.003', 'T1595'}
G0032_2 = {'T1587.001', 'T1573.001', 'T1593.001', 'T1566.002', 'T1070.004', 'T1584.001', 'T1134.002', 'T1497.003', 'T1140', 'T1585.003', 'T1546.004', 'T1090', 'T1027.009', 'T1041', 'T1132.001', 'T1204.002', 'T1083', 'T1562.003', 'T1071.001', 'T1608.001'}
G0032_3 = {'T1135', 'T1012', 'T1134.002', 'T1057', 'T1083', 'T1106', 'T1059.001', 'T1087.002', 'T1049', 'T1560.002', 'T1087.001', 'T1033', 'T1614', 'T1614.001', 'T1082', 'T1005', 'T1587.001', 'T1016', 'T1531', 'T1070.004'}
G0067_1 = {'T1033', 'T1053.005', 'T1025', 'T1027', 'T1189', 'T1010', 'T1203', 'T1074.001', 'T1059.007', 'T1567.002', 'T1082', 'T1083', 'T1119', 'T1547.001', 'T1106', 'T1055.002', 'T1016.001', 'T1539', 'T1518.001', 'T1016', 'T1056.001', 'T1071.001', 'T1124', 'T1102.002', 'T1005', 'T1059.006', 'T1113', 'T1020', 'T1560.002', 'T1555.003'}
G1005_1 = {'T1095', 'T1053.005', 'T1129', 'T1572', 'T1057', 'T1083', 'T1115', 'T1036.005', 'T1140', 'T1587.001', 'T1033', 'T1102.002', 'T1113', 'T1041', 'T1218.004', 'T1016', 'T1071.002', 'T1059.001', 'T1560.002', 'T1567.002', 'T1056.001', 'T1132.001', 'T1573.001', 'T1547.009', 'T1059.003', 'T1588.001', 'T1125', 'T1071.001', 'T1571', 'T1070.004', 'T1583.003', 'T1082', 'T1005'}





if __name__ == '__main__':
    print(get_procedure_example_by_technique_id('T1555.003'))