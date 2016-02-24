#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
pip install pygraphviz --install-option="--include-path=/usr/include/graphviz" --install-option="--library-path=/usr/lib/graphviz/"
"""

from __future__ import unicode_literals

import pygraphviz as pgv

# get data from database
host_vulnerable_list = ['N1(CVE-2014-6271)', 'N2(CVE-2012-2122)', 'N5(CVE-2015-0240)', 'N6(CVE-2015-5122)', 'N7(CVE-2014-8517)', 'N8(CVE-2008-4250)']

# get data from database
edge_list = [['测试者', 'N1(CVE-2014-6271)'],
        ['N1(CVE-2014-6271)', 'N2(CVE-2012-2122)'],
        ['N2(CVE-2012-2122)', 'N7(CVE-2014-8517)'], 
        ['N7(CVE-2014-8517)', 'N8(CVE-2008-4250)'],
        ['N1(CVE-2014-6271)', 'N5(CVE-2015-0240)'],
        ['N5(CVE-2015-0240)', 'N2(CVE-2012-2122)'],
        ['N5(CVE-2015-0240)', 'N6(CVE-2015-5122)'],
        ['N6(CVE-2015-5122)','N7(CVE-2014-8517)']
]

# vulneral_list = ['CVE-2014-6271', 'CVE-2012-2122', 'CVE-2015-0240', 'CVE-2015-5122', 'CVE-2014-8517', 'CVE-2008-4250']

g = pgv.AGraph(
    encoding='UTF-8',    # 为了可以显示中文
    # rankdir='LR',       # 从左到右，默认为 TB
    directed=True       # 有向图
)

g.add_node('测试者', fontname='Times New Roman', fontsize=12)
for vulneral in host_vulnerable_list:
    g.add_node(vulneral, fontname='Times New Roman', fontsize=12, shape = 'box', style='filled')

for edge in edge_list:
    g.add_edge(edge[0], edge[1])

#layout
g.layout('dot')
g.draw('attack.jpg', format='jpg')








