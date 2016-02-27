#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import pygraphviz as pgv

node_list = ['协同控制中心','任务规划','任务分发', '协同信息收集', '攻击路径生成','渗透攻击']

edge_list = [[node_list[0], node_list[1]],
             [node_list[1], node_list[2]],
             [node_list[3], node_list[4]],
             [node_list[4], node_list[5]]
]

st_end = ['开始', '结束']
g = pgv.AGraph(
    encoding='UTF-8',    # 为了可以显示中文
    # rankdir='LR',       # 从左到右，默认为 TB
    directed=True,       # 有向图
    splines=False,
    compound=True
)


# g.add_node(st_end[0], fontname='SimSun', fontsize=10.5, style='invis') #宋体
# g.add_node(st_end[1], fontname='SimSun', fontsize=10.5, style='filled') #宋体

for node in node_list:
    g.add_node(node, fontname='SimSun', fontsize=10.5, shape='box', style='filled') #宋体
#     g.add_node(vulneral, fontname='Times New Roman', fontsize=12, shape = 'box', style='filled')

for edge in edge_list:
    g.add_edge(edge[0], edge[1])


subg1 = g.add_subgraph([node_list[1], node_list[2]], name = 'cluster_node1', label='协同控制阶段', rank = 'same', style='dotted', color = 'black')
subg2 = g.add_subgraph([node_list[3], node_list[4], node_list[5]], name = 'cluster_node2', label='渗透测试阶段', rank = 'same', style='dotted', color = 'black')
subg3 = g.add_subgraph([node_list[0]], name = 'cluster_node3', label='', rank = 'same', color = 'black', style = 'invis')

g.add_edge(node_list[0], node_list[1], lhead='cluster_node1')
g.add_edge(node_list[0], node_list[3], lhead='cluster_node2')
# g.add_edge(node_list[2], node_list[3], lhead='cluster_node2', ltail='cluster_node1')

# layout: dot / fdp / neato / twopi(maybe good) / circo /circo
g.layout('dot')
g.draw('collabo-control.jpg', format='jpg')

















