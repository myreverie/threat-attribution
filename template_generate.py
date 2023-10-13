from tag_recognition import TagsRecognizer
from utils import *

import logging
from tqdm import tqdm

recognizer = TagsRecognizer()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
procedure_example_list = get_procedure_example_by_technique_id('T1190')
for procedure_text in tqdm(procedure_example_list):
    logger.debug(f'输入文本：{procedure_text}')
    tags_dict = recognizer.get_tags_from_text(procedure_text)
    logger.debug(f'标签识别结果{tags_dict}')
    print()