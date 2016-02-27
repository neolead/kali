#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import pygraphviz as pgv

node_list = ['网络扫描','可达性矩阵','脆弱性扫描', '原子攻击信息', '矩阵优化','攻击路径集合']

edge_list = [
             [node_list[0], node_list[1]],
             [node_list[1], node_list[2]],
             [node_list[2], node_list[3]],
             [node_list[3], node_list[4]],
             [node_list[4], node_list[5]]
]

st_end = ['开始', '结束']
g = pgv.AGraph(
    encoding='UTF-8',    # 为了可以显示中文
    rankdir='LR',       # 从左到右，默认为 TB
    directed=True       # 有向图
)


g.add_node(st_end[0], fontname='SimSun', fontsize=10.5, style='filled') #宋体
g.add_node(st_end[1], fontname='SimSun', fontsize=10.5, style='filled') #宋体

for node in node_list:
    g.add_node(node, fontname='SimSun', fontsize=10.5, shape='box', style='filled') #宋体
#     g.add_node(vulneral, fontname='Times New Roman', fontsize=12, shape = 'box', style='filled')

g.add_edge(st_end[0], node_list[0])
g.add_edge(node_list[5], st_end[1])
for edge in edge_list:
    g.add_edge(edge[0], edge[1])

#layout dot/fdp/sfdp/circo/neato/twopi
g.layout('neato') #maybe good

g.draw('attack-path.jpg', format='jpg')
