import pandas as pd

# make map: {ip source addr : n times the ip appears in log} 
ips = {}
f = open('dns_dst_only_2.jsonl', 'r')
for l in f:
    print(l)
    if l in ips:
        ips[l] += 1
    else:
        ips[l] = 1
f.close()

# sort values in descending order
df = pd.DataFrame.from_dict(ips, orient='index', columns=['count'])
df.sort_values(by='count', ascending=False)
print(df)