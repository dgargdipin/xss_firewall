import json
import pandas as pd
import matplotlib.pyplot as plt
import pickle as pkl

with open("fast.pkl","rb") as f:
    fast=pkl.load(f)
with open("slow.pkl","rb") as f:
    slow=pkl.load(f)


# df = pd.DataFrame({"fast": fast, "slow": slow})
# print(df.head)
# df.plot()
plt.plot(fast,'g')
plt.plot(slow,'y')
plt.show()
