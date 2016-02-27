#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import pygraphviz as pgv

node_list = ['进入系统(与)','获得权限（或）','猜测密码', '远程控制权限', '本地权限','哈希文件']

edge_list = [
             [node_list[0], node_list[1]],
             [node_list[0], node_list[2]],
             [node_list[1], node_list[3]],
             [node_list[1], node_list[4]],
             [node_list[2], node_list[5]]
]

g = pgv.AGraph(
    encoding='UTF-8',    # 为了可以显示中文
    # rankdir='LR',       # 从左到右，默认为 TB
    # directed=True       # 有向图
)

for node in node_list:
    g.add_node(node, fontname='SimSun', fontsize=10.5, shape='box', style='filled') #宋体
#     g.add_node(vulneral, fontname='Times New Roman', fontsize=12, shape = 'box', style='filled')

for edge in edge_list:
    g.add_edge(edge[0], edge[1], style='dotted')

#layout
g.layout('dot')
# g.layout('fdp')

g.draw('attack-tree.jpg', format='jpg')
