import matplotlib.pyplot as plt
plt.rcdefaults()
import numpy as np
import matplotlib.pyplot as plt
xlabels   = []
data_nums   = []
N = 12
# Read data
for line in file('./bar-data.txt'):
    info = line.split()
    # print "info, %s->%s" % (info[0], info[1])
    xlabels.append(info[0])
    data_nums.append(int(info[1]))

x_pos = np.arange(N)

width = 0.6
# Bar Plot
colors = ['g', 'g', 'g', 'm', 'm', 'c', 'g', 'c', 'r', 'r', 'c', 'g']
rect = plt.bar(x_pos, data_nums, width, color='g', align = 'center')

# Set the ticks on x-axis
plt.xticks(x_pos, xlabels)

# labels
plt.xlabel('Vulnerability Numbers / month')
plt.ylabel('Numbers')

# title
plt.title('2015 Vulnerability Numbers antiy to CNVD')

def autolabel(rects):
    # attach some text labels
    for rect in rects:
        height = rect.get_height()
        plt.text(rect.get_x() + rect.get_width()/2., 1.05*height,
                '%d' % int(height),
                ha='center', va='bottom')

autolabel(rect)
plt.show()
