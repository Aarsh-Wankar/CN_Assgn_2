file_list = ["urls_h1.txt", "urls_h2.txt", "urls_h3.txt", "urls_h4.txt"]
for file in file_list:
    with open(file, 'r') as f:
        lines = f.readlines()
    filtered_lines = []
    for line in lines:
        if len(line.strip().split(".")) > 1:
            filtered_lines.append(line)
    
    with open(f"f_{file}", "w+") as g:
        g.writelines(filtered_lines)
