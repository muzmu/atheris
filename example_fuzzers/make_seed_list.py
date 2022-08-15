import os

f = open("seeds.txt",'w');
for root, dirs, files in os.walk(os.path.abspath("./seeds/")):
    for file in files:
        f.write(os.path.join(root, file)+',')

f.close()
