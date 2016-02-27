#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
pip install pygraphviz --install-option="--include-path=/usr/include/graphviz" --install-option="--library-path=/usr/lib/graphviz/"
"""

from __future__ import unicode_literals

import pygraphviz as pgv

# get data from database
host_pri_list = ['host0:root', 'host1:root', 'host1:user', 'host2:root', 'host2:user']
# 0 1 2 3 4
# 1 2 5 6 7
label_list = ['mysql-vulnerable', 'apache-vulnerable', 'samba-vulnerable', 'ssh-vulnerable','ftp-vulnerable']

# get data from database
edge_list = [
             [host_pri_list[0], host_pri_list[1]],
             [host_pri_list[0], host_pri_list[2]],
             [host_pri_list[1], host_pri_list[3]],
             [host_pri_list[2], host_pri_list[3]],
             [host_pri_list[2], host_pri_list[4]]
]

g = pgv.AGraph(
    encoding='UTF-8',    # 为了可以显示中文
    # rankdir='LR',       # 从左到右，默认为 TB
    directed=True       # 有向图
)

for vulneral in host_pri_list:
    g.add_node(vulneral, fontname='Times New Roman', fontsize=10.5, shape = 'box', style='filled')

index = 0
for edge in edge_list:
    g.add_edge(edge[0], edge[1], fontname='Times New Roman', fontsize=10.5, label = label_list[index])
    index = index + 1

#layout
g.layout('dot')
g.draw('attack-graph-epl.jpg', format='jpg')
