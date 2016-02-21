import matplotlib.pyplot as plt
plt.rcdefaults()
import numpy as np
import matplotlib.pyplot as plt
ylabels   = []
data_nums   = []
N = 12
# Read data
for line in file('./barh-data.txt'):
    info = line.split('=')
    # print "info, %s->%s" % (info[0], info[1])
    ylabels.append(info[0])
    data_nums.append(int(info[1]))

y_pos = np.arange(N)
width = 0.8
# Bar Plot
colors = ['g', 'g', 'g', 'm', 'm', 'c', 'g', 'c', 'r', 'r', 'c', 'g']
rect = plt.barh(y_pos, data_nums, width, color=colors, align = 'center')

# Set the ticks on y-axis
plt.yticks(y_pos, ylabels)

# labels
plt.xlabel('People/Million')
plt.ylabel('big security incidents')

# title
plt.title('2015.SECURITY INCIDENTS')

def autolabel(rects):
    for rect in rects:
        height = rect.get_width() #for barh here shouldn't be rect.get_height()
        print height
        plt.text(rect.get_x()+1.00*height, rect.get_y() + rect.get_height()/2, "%s" % float(height))

autolabel(rect)
plt.show()
