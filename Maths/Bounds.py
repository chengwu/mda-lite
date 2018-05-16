
nks = [(0, 0), (0, 0), (6, 8), (11, 15), (16, 21),
        (21, 28), (27, 36), (33, 43), (38, 51), (44, 58), #8
        (51, 66), (57, 74), (63, 82), (70, 90), (76, 98), #13
        (83, 106), (90, 115), (96, 123), (103, 132), (110, 140), #18
        (117, 149), (124, 157), (131, 166), (138, 175), (145, 183), #23
        (152, 192), (159, 201), (167, 210), (174, 219), (181, 228), #28
        (189, 237), (196, 246), (203, 255), (211, 264), (218, 273), #33
        (226, 282), (233, 291), (241, 300), (248, 309), (256, 319), #38
        (264, 328), (271, 337), (279, 347), (287, 356), (294, 365), #43
        (302, 375), (310, 384), (318, 393), (326, 403), (333, 412), #48
        (341, 422), (349, 431), (357, 441), (365, 450), (373, 460), #53
        (381, 470), (389, 479), (397, 489), (405, 499), (413, 508), #58
        (421, 518), (429, 528), (437, 537), (445, 547), (453, 557), #63
        (462, 566), (470, 576), (478, 586), (486, 596), (494, 606), #68
        (502, 616), (511, 625), (519, 635), (527, 645), (535, 655), #73
        (544, 665), (552, 675), (560, 685), (569, 695), (577, 705), #78
        (585, 715), (594, 725), (602, 735), (610, 745), (619, 755), 
        (627, 765), (635, 775), (644, 785), (652, 795), (661, 805),
        (669, 815), (678, 825), (686, 835), (695, 845), (703, 855),
        (712, 866), (720, 876), (729, 886), (737, 896), (746, 906)]

def get_nks():
    nks95 = []
    nks99 = []
    for b in nks:
        nks95.append(b[0])
        nks99.append(b[1])
    return nks95, nks99


# Probability to discover a new interface given K total interfaces and
# k discovered interfaces
def probability_diagonal_transition(K, k):
    result = float(K-k) / K
    return result

# Probability to NOT discover a new interface given K total interfaces and
# k discovered interfaces
def probability_horizontal_transition(K, k):
    result = float(k) / K
    return result


def probability_space(K, nks):
    probability_space_2_d =[[None] * (nks[x] + 1) for x in xrange(1, K+2)]

    probability_space_2_d[1][0] = 0
    probability_space_2_d[1][1] = 1

    # Init special case k = 1
    for i in range(1, nks[2] + 1):
        if i != 1:
            probability_space_2_d[1][i] = probability_space_2_d[1][i - 1] * probability_horizontal_transition(K, 1)

    for k in range(2, K + 1):
        for i in range(k, nks[k+1] + 1):
            if k == i:
                probability_space_2_d[k][i] = probability_space_2_d[k-1][i-1] * probability_diagonal_transition(K, k-1)
            elif i > k and i <= nks[k]:
                probability_space_2_d[k][i] =\
                probability_space_2_d[k-1][i-1] * probability_diagonal_transition(K, k-1) + \
                probability_space_2_d[k][i-1] * probability_horizontal_transition(K, k)
            else:
                probability_space_2_d[k][i] = \
                    probability_space_2_d[k][i - 1] * probability_horizontal_transition(K, k)

    return probability_space_2_d


probability_space_3_d = []
# K_max the maximum of interfaces to discover
def fill_probability_space(nks, K_max = 128):
    probability_space_3_d.append([])
    probability_space_3_d.append([])
    for K in range(2, K_max + 1):
        probability_space_3_d.append(probability_space(K, nks))



# K number of interfaces to discover
# n number of probes sent
def expectation_discovered(nks, K, n):
    expectation = 0.0
    for k in range(1, K+1):
        if n <= nks[k]:
            expectation += k*probability_space_3_d[K][k][n]
    return expectation


if __name__ == "__main__":
    print nks[32][1]
    print nks[4][1]
    print "Test"
    fill_probability_space(get_nks()[1], 40)

    print expectation_discovered(get_nks()[1], 4, 8)
    print expectation_discovered(get_nks()[1], 6, 8)