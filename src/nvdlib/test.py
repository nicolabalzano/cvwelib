import sys
import os

# Aggiungi la directory 'src' al percorso di ricerca di Python
# Questo permette di trovare il modulo 'utils'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import NVDHelper as nh
nh.build_search_index()