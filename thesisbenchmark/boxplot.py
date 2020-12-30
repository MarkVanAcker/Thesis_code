
# Import libraries 
import matplotlib.pyplot as plt 
import numpy as np 
  
  
# Creating dataset 

with open("enclave_startup.txt") as f:
    data = [int(x) for x in f.read().split()]
  
fig = plt.figure(figsize =(10, 7)) 
  
# Creating plot 
plt.boxplot(data) 
plt.ylabel("execution time in ms")
plt.tick_params(
    axis='x',          # changes apply to the x-axis
    which='both',      # both major and minor ticks are affected
    bottom=False,      # ticks along the bottom edge are off
    top=False,         # ticks along the top edge are off
    labelbottom=False) # labels along the bottom edge are off
# show plot 
plt.show() 

