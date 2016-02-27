#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import pygraphviz as pgv

node_list = ['踩点','地址和域名','扫描', '开放端口', '漏洞扫描','攻击','口令猜测', '获取权限','生成报告', '拒绝服务攻击', '邮箱', '社会工程学']

#['授权', '踩点'],
edge_list = [
             ['踩点', '地址和域名'],
             ['地址和域名', '扫描'],
             ['扫描', '开放端口'],
             ['扫描', '口令猜测'],
             ['开放端口', '漏洞扫描'],
             ['漏洞扫描', '攻击'],
             ['攻击', '获取权限'],
             ['口令猜测', '获取权限'],
             ['获取权限', '生成报告'],
             ['地址和域名', '拒绝服务攻击'],
             ['踩点', '邮箱'],
             ['邮箱', '社会工程学'],
             ['社会工程学', '获取权限']
]
g = pgv.AGraph(
    encoding='UTF-8',    # 为了可以显示中文
    # rankdir='LR',       # 从左到右，默认为 TB
    directed=True       # 有向图
)

for node in node_list:
    g.add_node(node, fontname='SimSun', fontsize=10.5, shape='box', style='filled') #宋体
#     g.add_node(vulneral, fontname='Times New Roman', fontsize=12, shape = 'box', style='filled')

for edge in edge_list:
    g.add_edge(edge[0], edge[1])

#layout
g.layout('dot')
# g.layout('neato')

g.draw('attack-example.jpg', format='jpg')
