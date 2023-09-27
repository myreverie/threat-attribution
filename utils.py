from mitreattack.stix20 import MitreAttackData

from collections import defaultdict

import numpy as np

mitre_attack_data = MitreAttackData("./cti/enterprise-attack/enterprise-attack.json")
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

TECHNIQUES_NUM = len(get_techniques())
GROUPS_NUM = len(get_group2techniques_data().keys())
TECHNIQUE_ATTCK_ID_TO_INDEX = get_technique_attck_id_to_index(get_techniques())
GROUP_ATTCK_ID_TO_INDEX = get_group_attck_id_to_index(get_group2techniques_data().keys())
APT29_1_techniques = {'T1021.001', 'T1036.005', 'T1078.003', 'T1133', 'T1546.003', 'T1550.001', 'T1003.006', 'T1069.002', 'T1482', 'T1213', 'T1078.004', 'T1555.003', 'T1057', 'T1003.001', 'T1539', 'T1098.001', 'T1595.001', 'T1087.002'}
APT29_2_techniques = {'T1566.003', 'T1204.001', 'T1610', 'T1566.002', 'T1071.001'}
kimsuky_1_techniques = {'T1546.001', 'T1055', 'T1056.001', 'T1218.005', 'T1505.003', 'T1074.001', 'T1082', 'T1189', 'T1021.001', 'T1562.004', 'T1219', 'T1003', 'T1566.002', 'T1566.001', 'T1059.001', 'T1560', 'T1547', 'T1070.004', 'T1550.002', 'T1040', 'T1573.001', 'T1185', 'T1059.006', 'T1114.003', 'T1547.001', 'T1083', 'T1548.002'}
APT28_1_techniques = {'T1036.003', 'T1074.002', 'T1078', 'T1560.001', 'T1098.002', 'T1110.003', 'T1021.002', 'T1213', 'T1048.002', 'T1030', 'T1036.005', 'T1078.002', 'T1114.002', 'T1505.003', 'T1115', 'T1003.001', 'T1003.003', 'T1036', 'T1005', 'T1039', 'T1190'}
APT29_3_techniques = {'T1059.005', 'T1078', 'T1190', 'T1195.002', 'T1505.003', 'T1199', 'T1595.002'}
Turla_1_techniques = {'T1559', 'T1078', 'T1587.001', 'T1119', 'T1132.002', 'T1564', 'T1036', 'T1027.002', 'T1003', 'T1482', 'T1046', 'T1112', 'T1573.001', 'T1083', 'T1106', 'T1547.006', 'T1074', 'T1132', 'T1071.001', 'T1104', 'T1190', 'T1546.016', 'T1569.002', 'T1573.002', 'T1071', 'T1588', 'T1040', 'T1572', 'T1027', 'T1055.001', 'T1059.001', 'T1584', 'T1560.003', 'T1140', 'T1090.003', 'T1610', 'T1071.003', 'T1056.001', 'T1001', 'T1608', 'T1095', 'T1135', 'T1570', 'T1071.004', 'T1001.003', 'T1574.002', 'T1573', 'T1014'}
