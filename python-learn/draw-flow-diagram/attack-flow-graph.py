#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
pip install pygraphviz --install-option="--include-path=/usr/include/graphviz" --install-option="--library-path=/usr/lib/graphviz/"
"""

from __future__ import unicode_literals

import pygraphviz as pgv

# get data from database
host_pri_list = ['N1(root)', 'N2(root)', 'N5(root)', 'N6(root)', 'N7(root)', 'N8(admin)']
num_list = [1,2,5,6,7,8]
# 0 1 2 3 4 5
# 1 2 5 6 7 8

# get data from database
edge_list = [['测试者', host_pri_list[0]],
             [host_pri_list[0], host_pri_list[1]],
             [host_pri_list[1], host_pri_list[4]],
             [host_pri_list[4], host_pri_list[5]],
             [host_pri_list[0], host_pri_list[2]],
             [host_pri_list[2], host_pri_list[1]],
             [host_pri_list[2], host_pri_list[3]],
             [host_pri_list[3], host_pri_list[4]]
]

g = pgv.AGraph(
    encoding='UTF-8',    # 为了可以显示中文
    # rankdir='LR',       # 从左到右，默认为 TB
    directed=True       # 有向图
)

g.add_node('测试者', fontname='SimSun', fontsize=10.5)
for vulneral in host_pri_list:
    g.add_node(vulneral, fontname='Times New Roman', fontsize=10.5, shape = 'box', style='filled')

for edge in edge_list:
    g.add_edge(edge[0], edge[1], fontname='Times New Roman', fontsize=10.5, label = 'exploit[' + str(num_list[host_pri_list.index(edge[1])]) + ']' )

#layout
g.layout('dot')
g.draw('attack-graph.jpg', format='jpg')
