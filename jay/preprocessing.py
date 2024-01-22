import json

a = open("A.jsonl", "w+")
#no_a = open("no_A.jsonl", "w+")
n = 0
with open("../../../traffic/jay/dns_2.jsonl") as f:
    for line in f:
        l = json.loads(line)
        written = False
        data = l['data']
        resp = data['response']
        query = data['query']
        if resp and query:
            code = resp['response_code']
            answers = resp['answers']
            if code == 'NoError':
                for answer in answers:
                    if 'A' in answer['data']:
                        a.write(line)
                        written = True
                        break
        #if not written:
        #    no_a.write(line)
        n += 1
        if n % 1000000 == 0:
            print(n, " lines read")
