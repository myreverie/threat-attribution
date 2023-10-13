import logging
# logging.basicConfig(format='[%(levelname)s] %(message)s', filemode='w', filename='./log/test.log')
logging.basicConfig(format='[%(levelname)s] %(message)s')

import spacy
import srsly

from ioc_finder import find_iocs
import re
from utils import *
from collections import defaultdict
from transformers import pipeline
from transformers import AutoTokenizer, AutoModelForTokenClassification

from tqdm import tqdm

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)



regex_tuple = [
    ('Observed-data/Filename', r'\b[A-Za-z0-9-_\.]+\.(?:txt|php|exe|dll|bat|sh|sys|htm|html|js|jar|jpg|png|vb|scr|pif|chm|zip|rar|cab|pds|docx|doc|ppt|pptx|xls|xlsx|swf|gif|ps|tmp|lnk)'),
    ('Tool/Cmdlet', r'(?:Get|Set)-[A-Za-z]+')
]
sparql_tuple = [
    ('Tool/Windows-commands', 'SELECT ?cmd WHERE { {?cmd dbo:genre <http://dbpedia.org/resource/Command_(computing)>.} UNION {?cmd dbp:wikiPageUsesTemplate dbt:Windows_commands .} }'),
    ('Tool', 'SELECT ?software WHERE {?software a dbo:Software.}'),
    ('Tool/Cipher', 'SELECT ?cipher WHERE {?cipher a yago:Cipher106254239.}'),
    ('Tool/Protocol', 'SELECT ?protocol WHERE { {?protocol dbo:wikiPageWikiLink dbr:Communications_protocol .} UNION {?protocol dbo:wikiPageWikiLink dbc:Internet_protocols .} }'),
    ('Tool/Encoding', 'SELECT ?encoding WHERE {?encoding a yago:Encoding100615887.}'),
    ('Tool/Windows_Components', 'SELECT ?software WHERE {?software dbp:wikiPageUsesTemplate	 dbt:Windows_Components .}'),
    ('Term/Operating-System', 'SELECT ?os WHERE {?os dbp:wikiPageUsesTemplate dbt:Operating_system .}')
]
types_filter_tuple = [
    ('Tool', 'DBpedia:Software'),
    ('Identity', 'DBpedia:Company'),
    ('Tool/Programming-Language', 'DBpedia:ProgrammingLanguage'),
    ('Tool/Website', 'DBpedia:Website')
]

text = 'The threat actor regularly tasklist other systems using tasklist.exe'
text2 = 'During the SolarWinds Compromise, APT29 stole users\' saved passwords from Chrome.'
text3 = 'The threat actor used accounts with Delegated Administrator rights to access other O365 tenants. The Threat actor also used valid accounts to create persistence within the environment.'
text4 = 'During the SolarWinds Compromise, APT29 used PowerShell to discover domain accounts by exectuing Get-ADUser and Get-ADGroupMember.'
text5 = 'The threat actor used both privileged and non-privileged accounts for RDP throughout the environment, depending on the target system'

class TagsRecognizer():
    def __init__(self) -> None:
        self.tags_dict = None
        # 加载SecureBERT-NER模型
        tokenizer = AutoTokenizer.from_pretrained('./model/SecureBERT-NER')
        model = AutoModelForTokenClassification.from_pretrained('./model/SecureBERT-NER')
        # aggregation_strategy还有first和average
        self.ner = pipeline('ner', model=model, tokenizer=tokenizer, aggregation_strategy='max')

        # 加载自定义规则库
        self.ruler_nlp = spacy.blank('en')
        ruler = self.ruler_nlp.add_pipe('entity_ruler')
        lotl_patterns = srsly.read_jsonl('./data/custom-knowledge-base/lotl.jsonl')
        test_patterns = srsly.read_jsonl('./data/custom-knowledge-base/test.jsonl')
        winapi_patterns = srsly.read_jsonl('./data/custom-knowledge-base/winapi.jsonl')
        ruler.add_patterns(lotl_patterns)
        ruler.add_patterns(test_patterns)
        ruler.add_patterns(winapi_patterns)

    def regex_process(self, text):
        """基于正则表达式的标注"""
        # 自建正则集(custom_regex)
        for tag_type, pattern in regex_tuple:
            results = re.findall(pattern, text)
            for result in results:
                self.tags_dict[result].append((tag_type, 'custom_regex'))
                logger.debug(f'custom_regex 识别出了 {tag_type} 类型的实体：{result}')
            if tag_type == 'Observables/Filename':
                #TODO: 用知识库识别不带扩展名的文件名，看是否是已知工具
                pass
        # ioc_finder处理
        iocs = find_iocs(text)
        for cve_id in iocs['cves']:
            self.tags_dict[cve_id].append(('Vulnerability/CVE-id', 'ioc_finder'))
            logger.debug(f'ioc finder 识别出了 Vulnerability/CVE_id 类型的实体：{cve_id}')
        for domain in iocs['domains']:
            self.tags_dict[domain].append(('Observed-data/Domain', 'ioc_finder'))
            logger.debug(f'ioc finder 识别出了 Observed-data/Domain 类型的实体：{domain}')

    def kb_process(self, text):
        """基于公开知识库匹配的标注"""
        nlp = spacy.blank('en')
        nlp.add_pipe('dbpedia_spotlight', config={'confidence': 0.01, 'process': 'annotate'})
        for tag_type, sparql in sparql_tuple:
            nlp.get_pipe('dbpedia_spotlight').sparql = sparql
            doc = nlp(text)
            # print([(ent.text, ent.kb_id_, ent._.dbpedia_raw_result['@similarityScore']) for ent in doc.ents], tag_type)
            for ent in doc.ents:
                self.tags_dict[ent.text].append((tag_type, 'sparql_filter'))
                logger.debug(f'sparql filter 识别出了 {tag_type} 类型的实体：{ent.text}')
        nlp.get_pipe('dbpedia_spotlight').sparql = None
        for tag_type, types_filter in types_filter_tuple:
            nlp.get_pipe('dbpedia_spotlight').types = types_filter
            doc = nlp(text)
            # print([(ent.text, ent.kb_id_, ent._.dbpedia_raw_result['@similarityScore']) for ent in doc.ents], tag_type)
            for ent in doc.ents:
                self.tags_dict[ent.text].append((tag_type, 'types_filter'))
                logger.debug(f'types filter 识别出了 {tag_type} 类型的实体：{ent.text}')

    def custom_rule_based_process(self, text):
        """基于自建知识库匹配的标注"""
        doc = self.ruler_nlp(text)
        for ent in doc.ents:
            self.tags_dict[ent.text].append((ent.label_, 'custom_ruler'))
            logger.debug(f'custom ruler 识别出了 {ent.label_} 类型的实体：{ent.text}')

    def LLM_process(self, text):
        """基于LLM的标注"""
        results = self.ner(text)
        logger.debug(f'LLM的NER结果：{results}')
        for result in results:
            # 去除可能存在的空格
            result['word'] = result['word'].strip()
            if result['entity_group'] == 'APT':
                self.tags_dict[result['word']].append(('ThreatActor', 'SecureBERT_NER'))
                logger.debug(f'SecureBERT NER 识别出了 ThreatActor 类型的实体：{result["word"]}')
            if result['entity_group'] == 'MAL' and result['score'] > 0.75:
                self.tags_dict[result['word']].append(('Malware', 'SecureBERT_NER'))
                logger.debug(f'SecureBERT NER 识别出了 Malware 类型的实体：{result["word"]}')

    def tags_merge(self):
        # 合并不同模块产生的标签
        for tag_item_list in self.tags_dict.values():
            # MAL误报较高，因此优先考虑SecureBERT NER以外的标签
            if ('Malware', 'SecureBERT_NER') in tag_item_list:
                if {item[1] for item in tag_item_list}.difference({'SecureBERT_NER'}):
                    tag_item_list.remove(('Malware', 'SecureBERT_NER'))
                    logger.debug('标签合并：SecureBERT_NER与其他模块判断存在冲突，以其他模块的结果为准')

            # 识别出二级标签的，以二级标签为准
            if 2 in [len(item[0].split('/')) for item in tag_item_list]:
                to_be_removed_item_list = [item for item in tag_item_list if len(item[0].split('/')) == 1]
                for item in to_be_removed_item_list:
                    tag_item_list.remove(item)
                    logger.debug(f'标签合并：一级标签 {item} 和其他二级标签同时出现，以二级标签为准')

        # 消除模块溯源信息，并去重
        for key in self.tags_dict:
            self.tags_dict[key] = list(set([item[0] for item in self.tags_dict[key]]))

    def get_tags_from_text(self, text):
        """从文本中标注标签"""
        self.tags_dict = defaultdict(list)
        self.regex_process(text)
        self.LLM_process(text)
        self.custom_rule_based_process(text)
        self.kb_process(text)
        logger.debug(f'融合前的标签：{self.tags_dict}')
        self.tags_merge()
        logger.debug(f'融合后的标签：{self.tags_dict}')

        return self.tags_dict


if __name__ == '__main__':
    # r = find_iocs('Emotet has been seen exploiting SMB via a vulnerability exploit like EternalBlue (MS17-010) to achieve lateral movement and propagation.')
    # print(r)
    recognizer = TagsRecognizer()
    tags_dict = recognizer.get_tags_from_text('POLONIUM has used OneDrive, Dropbox, and Mega cloud storage to store stolen information.')
    # procedure_example_list = get_procedure_example_by_technique_id('T1190')
    # for procedure_text in tqdm(procedure_example_list):
    #     logger.debug(f'输入文本：{procedure_text}')
    #     tags_dict = recognizer.get_tags_from_text(procedure_text)
