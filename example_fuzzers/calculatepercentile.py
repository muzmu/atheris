import numpy as np
import os
import sys


arr =[]
files = os.listdir(sys.argv[1])
for ele in files:
  tmp=ele.split('-')
  try:
    arr.append(float(tmp[0]))
  except:
    None

distance_per1=np.percentile(arr, 1)
print(distance_per1)


final_files = []
for ele in files:
  tmp=ele.split('-')
  try:
    if float(tmp[0]) <= distance_per1:
      final_files.append(ele)
  except:
    None

print(final_files)
  
