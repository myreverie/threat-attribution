import json

def lolbas():
    with open('./data/custom-knowledge-base/lolbas.json', 'r') as f:
        data = json.loads(f.read())
        for i in data:
            print(json.dumps({'label': 'Tool/LivingOffTheLand', 'pattern': [{'LOWER': i['Name'].lower()}]}))

def winapi():
    with open('./data/custom-knowledge-base/winapi_functions_by_category.json', 'r') as f:
        data = json.loads(f.read())
    with open('./data/custom-knowledge-base/winapi.jsonl', 'w') as f:
        for i in data:
            for j in data[i]:
                f.write(json.dumps({'label': 'Tool/Windows-API', 'pattern': [{'LOWER': j.lower()}]})+'\n')
winapi()