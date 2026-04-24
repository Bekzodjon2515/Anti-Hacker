import os
import glob

files = glob.glob('handlers/*_handler.py')
for file in files:
    with open(file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    if '{5}' in content:
        content = content.replace('{5}', '{RATE_LIMIT}')
        
        # Ensure config import is added
        if 'RATE_LIMIT' not in content:
            if 'from config import ' in content:
                content = content.replace('from config import ', 'from config import RATE_LIMIT, ')
            else:
                content = 'from config import RATE_LIMIT\n' + content
                
        with open(file, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f'Updated {file}')
