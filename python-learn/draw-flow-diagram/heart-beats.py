#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import pygraphviz as pgv

node_list = ['获取节点','设定定时器','发送报文', '等待回复', '超时', '加入队列', '下一个节点']

edge_list = [
             [node_list[0], node_list[1]],
             [node_list[1], node_list[2]],
             [node_list[2], node_list[3]],
             [node_list[3], node_list[4]],
             [node_list[4], node_list[5]],
             [node_list[4], node_list[6]],
             [node_list[6], node_list[1]]
]

st_end = ['开始', '结束']
g = pgv.AGraph(
    encoding='UTF-8',    # 为了可以显示中文
    # rankdir='LR',       # 从左到右，默认为 TB
    directed=True       # 有向图
)

g.add_node(st_end[0], fontname='SimSun', fontsize=10.5, style='filled') #宋体
g.add_node(st_end[1], fontname='SimSun', fontsize=10.5, style='filled') #宋体

for node in node_list:
    if node == node_list[4]:
        g.add_node(node, shape='diamond', fontname='SimSun', fontsize=10.5, style='filled') #宋体
    else:
        g.add_node(node, fontname='SimSun', fontsize=10.5, shape='box', style='filled') #宋体

for edge in edge_list:
    if edge[0] == node_list[4] and edge[1] == node_list[6]:
        g.add_edge(edge[0], edge[1], label = 'NO', fontname='Times New Roman', fontsize=10.5)
    elif edge[0] == node_list[4] and edge[1] == node_list[5]:
        g.add_edge(edge[0], edge[1], label = 'YES', fontname='Times New Roman', fontsize=10.5)
    else:
        g.add_edge(edge[0], edge[1])
g.add_edge(st_end[0], node_list[0])
g.add_edge(node_list[len(node_list) - 2], st_end[1])

sub = g.add_subgraph([node_list[4], node_list[6], 'ad'], rank='same', name = 'cluster_n1')
#layout dot/ fdp/ circo /neato /twopi
g.layout('dot')
g.draw('heart-beat.jpg', format='jpg')
