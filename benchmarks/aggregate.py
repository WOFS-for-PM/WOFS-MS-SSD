#!/usr/bin/env python3

import csv
import math
import sys

table_name = sys.argv[1]
grp = int(sys.argv[2])

def is_number(s):
    try:  
        float(s)
        return True
    except ValueError:  
        pass  
    try:
        import unicodedata 
        unicodedata.numeric(s) 
        return True
    except (TypeError, ValueError):
        pass
    return False

def agg_table(table:str, grp:int):
    content = []
    content_copy = []
    with open(table, 'r') as i_f:
        cols = i_f.readline().strip().split(" ")
        rows = 0
        i_f.seek(0)
        
        reader = csv.DictReader(i_f, delimiter=' ')    

        for row in reader:
            rows += 1
            content.append(row)
        
        content_copy = content.copy()

        rows_per_grp = rows // grp
        
        for row in range(rows):
            line = content[row]
            if row >= rows_per_grp:
                for col in cols:
                    if is_number(line[col]):
                        orig_line = 0
                        cur_line = 0
                        if str.isdigit(str(content[row % rows_per_grp][col])):
                            orig_line = int(content[row % rows_per_grp][col])
                        else:
                            orig_line = float(content[row % rows_per_grp][col])
                        
                        if str.isdigit(str(line[col])):
                            cur_line = int(line[col])
                        else:
                            cur_line = float(line[col])

                        content[row % rows_per_grp][col] = orig_line
                        content[row % rows_per_grp][col] += cur_line
        
        for row in range(rows_per_grp):
            for col in cols:
                if is_number(content[row][col]):
                    if str.isdigit(str(content[row][col])):
                        content[row][col] = int(content[row][col])
                        content[row][col] = content[row][col] // grp
                    else:
                        content[row][col] = float(content[row][col])
                        content[row][col] /= grp
        
        # calculate the standard deviation
        for row in range(rows):
            line = content_copy[row]
            for col in cols:
                if is_number(line[col]):
                    if str.isdigit(str(line[col])):
                        average = int(content[row % rows_per_grp][col])
                        if content[row].get("std-"+col) is not None:
                            content[row % rows_per_grp]["std-"+col] += (int(content_copy[row][col]) - average) ** 2
                        else:
                            content[row % rows_per_grp]["std-"+col] = ((int(content_copy[row][col]) - average) ** 2)
                    else:
                        average = float(content[row % rows_per_grp][col])
                        if content[row].get("std-"+col) is not None:
                            content[row % rows_per_grp]["std-"+col] += (float(content_copy[row][col]) - average) ** 2
                        else:
                            content[row % rows_per_grp]["std-"+col] = (float(content_copy[row][col]) - average) ** 2

        # calculate the average of the standard deviation
        for row in range(rows_per_grp):
            for col in cols:
                if content[row].get("std-"+col) is not None and is_number(content[row]["std-"+col]):
                    if str.isdigit(str(content[row]["std-"+col])):
                        content[row]["std-"+col] = int(content[row]["std-"+col])
                        content[row]["std-"+col] = math.sqrt(content[row]["std-"+col] // (grp - 1)) if grp > 1 else 0 
                    else:
                        content[row]["std-"+col] = float(content[row]["std-"+col])
                        content[row]["std-"+col] = math.sqrt(content[row]["std-"+col] / (grp - 1)) if grp > 1 else 0

    with open(table + "_agg", 'w') as o_f:
        writer = csv.writer(o_f, delimiter=' ')
        first_row = []
        for col in cols:
            first_row.append(col)
        for col in cols:
            if content[0].get("std-"+col) is not None:
                first_row.append("std-"+col)
        writer.writerow(first_row)
        for row in range(rows_per_grp):
            line = []
            for col in cols:
                line.append(content[row][col])
            for col in cols:
                if content[row].get("std-"+col) is not None:
                    line.append(content[row]["std-"+col])
            writer.writerow(line)

agg_table(table_name, grp)