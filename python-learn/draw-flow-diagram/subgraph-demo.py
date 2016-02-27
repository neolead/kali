#!/usr/bin/env python
# -*- coding: utf-8 -*-

# subgraph
import pygraphviz

g = pygraphviz.AGraph(
    encoding='UTF-8',   # 为了可以显示中文
    rankdir='LR',       # 从左到右，默认为 TB
    directed=True,      # 有向图
    compound=True
)

g.add_node('node0')
g.add_node('node1')
g.add_node('node2')
g.add_node('node3')

# subgraph
g.add_subgraph(['node2', 'node3'], name='cluster_nodes', rank='same', style='dotted', color='black')

g.add_edge('node0', 'node2')
g.add_edge('node1', 'node3', lhead='cluster_nodes')

# dot / fdp / neato / twopi / circo /circo
g.layout('dot')
g.draw('subgraph.jpg', format='jpg')
