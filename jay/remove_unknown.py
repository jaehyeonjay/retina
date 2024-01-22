import json

out = open("no_unknown.jsonl", "w+")
cnt = 0
with open("A.jsonl") as f:
    for line in f:
        l = json.loads(line)

        ns = l['data']['response']['answers']
        additionals = l['data']['response']['additionals']
        ans = l['data']['response']['answers']
        
        for i in range(len(ns)):
            if ns[i]['data'] == "Unknown":
                ns[i]['data'] = None

        for i in range(len(ans)):
            if ans[i]['data'] == "Unknown":
                ans[i]['data'] = None

        for i in range(len(additionals)):
            if additionals[i]['data'] == "Unknown":
                additionals[i]['data'] = None
        
        cnt += 1
        if cnt % 1000000 == 0:
            print(cnt, " lines read")
        
        out.write(json.dumps(l)+'\n')
out.close()
