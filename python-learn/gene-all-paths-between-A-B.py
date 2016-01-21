class Graph:
    """
    求得图（DAG还是无向图？）中两点间所有路径， 此算法不错，仔细体会
    """
    def __init__(self):
        self.matrix1=[[0,1,1,0,0,0,0,0],
                     [-1,0,0,1,1,0,0,0],
                     [-1,0,0,0,0,1,0,0],
                     [0,-1,0,0,0,0,1,0],
                     [0,-1,0,0,0,0,0,1],
                     [0,0,-1,0,0,0,0,1],
                     [0,0,0,-1,0,0,0,1],
                     [0,0,0, -1,-1,-1,0]
                    ]
        self.matrix = [
                        [0,1,1,1,0],
                        [1,0,1,1,1],
                        [1,1,0,1,1],
                        [1,1,1,0,1],
                        [0,1,1,1,0]
                      ]
        self.paths = []

    def is_not_in_stack(self, stack, i, j):
        if i not in stack and j not in stack:
            return True
        return False

    def update_arcStatus(self, stack, arc_status, vex):
            N = len(arc_status)
            for i in range(N):
                if i not in stack:
                    arc_status[vex][i] = False
                    arc_status[i][vex] = False

    def get_path(self):
        N = len(self.matrix)
        vertex_status = [False for i in range(N)]
        arc_status =  [[False] * N for row in range(N)]
        stack = []
        stack.append(0)
        vertex_status[0] = True
        while len(stack):
            vex = stack[len(stack) - 1]
            if vex == N - 1:
                self.paths.append(stack[:]) #为什么必须是stack[:]，而不能是stack[]
                print(self.paths)
                vertex_status[vex] = False
                stack.pop() #必须先弹出栈顶的vex，然后再执行后面的update，将与vex有关的不在栈内的边全部重置为False
                self.update_arcStatus(stack, arc_status, vex)
            else:
                i = 0
                while i < N:
                    if self.matrix[vex][i] and vertex_status[i] == False and arc_status[vex][i] == False:
                        vertex_status[i] = True
                        arc_status[vex][i] = True
                        stack.append(i)
                        break
                    i += 1
                if i == N:
                    vertex_status[vex] = False
                    stack.pop()#必须先弹出栈顶的vex，然后再执行后面的update，将与vex有关的不在栈内的边全部重置为False
                    self.update_arcStatus(stack, arc_status, vex)

        print("GET THE PATH: ")
        print(self.paths)
if __name__ == "__main__":
    graph = Graph()
    graph.get_path()
