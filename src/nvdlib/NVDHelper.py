import sys
sys.path.append('src')
import logging
logging.basicConfig(stream = sys.stderr, level = logging.DEBUG)
from datetime import datetime
from copy import deepcopy
from utils.Utils import save_to_json_file, get_json_from_file, check_cve, check_cwe
import requests
import lzma
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

__ignored_status = ['Rejected', 'Received']
__quarantined_status = ['Undergoing Analysis', 'Awaiting Analysis']
MAX_WORKERS = 4 # Maximum number of threads for parallel CVE retrieval

def __get_json_data_from_xz(url: str) -> dict:
    """
        Desc:
            Method to retrieve data in .json.xz format from a given url, decompress it and return it in json format
        Params:
            :param url: the url to fetch data from
        Returns:
            The requested .json data
    """
    response = requests.get(url)
    decompressed_data = lzma.decompress(response.content)
    return json.loads(decompressed_data.decode('utf-8'))


def __get_modified_cve_years() -> set:
    """
        Desc:
            Method to get modified CVEs up to the last 8 days. The data is pulled from the following repository:
            https://github.com/fkie-cad/nvd-json-data-feeds by fkie-cad\n
            Only if the current system does not have a record of modified data, or it does not match the latest update
            data will be automatically updated for every CVE year included in the modified json
        Returns:
            set of the modified CVE years
    """
    try:
        last_modified = get_json_from_file("CVE-Modified.json")
    except FileNotFoundError:
        last_modified = None

    request_link = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-Modified.json.xz"
    formatted_data = __get_json_data_from_xz(request_link)

    if last_modified != None and last_modified['timestamp'] == formatted_data['timestamp']:
        logging.info("Data already up-to-date")
        return set([])
    
    out = []
    for cve in formatted_data['cve_items']:
        out.append((str(cve['id']).split('-'))[1])
    
    save_to_json_file(formatted_data, "CVE-Modified.json")
    return set(out)


def check_for_updates():
    """
        Desc:
            Method to check for data update. It uses an internal call to get all the modified CVEs up to the last 8 days. 
            The data is pulled from the following repository:
            https://github.com/fkie-cad/nvd-json-data-feeds by fkie-cad\n
            Only if the current system does not have a record of modified data, or it does not match the latest update
            data will be automatically updated for every CVE year included in the modified json
    """
    modified_years = __get_modified_cve_years()
    if len(modified_years) > 0:
        [save_one_year_json(int(year)) for year in modified_years]
        logging.info(f'Data updated for years: {[year for year in modified_years]}')


def start_up_server(debug: bool = False) -> bool:
    """
        Desc:
            Method to start-up the local sever
        Returns:
            True if the start-up process ends correctly
    """
    if debug:
        return True
    return save_all_years_json()


def save_one_year_json(year: int) -> int:
    """
        Desc:
            This method allows the retrieval (and local save) of a specified year CVE dataset from the following repository:
            https://github.com/fkie-cad/nvd-json-data-feeds by fkie-cad
            The data is downloaded in .xz format, extracted and saved to .json in the local /_data folder in the format 'CVE-<YEAR>.json'.
        Params:
            :param year: The desired year to fetch
        Returns:
            :returns: The count of requested year CVEs
        Raises:
            :raises ValueError: if the selected year is not valid. Must be in the range [1999, datetime.now().year]
    """
    if year < 1999 or year > datetime.now().year:
        raise ValueError('Invalid input value: please insert valid year from 1999 to today.')
    
    if not os.path.isdir("./src/_data/"): # check if _data folder exists
        os.makedirs("./src/_data/")
    
    if not os.path.isdir(f"./src/_data/{year}"): # check if 'year' folder exists
        os.makedirs(f"./src/_data/{year}")
    
    request_link = f"https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{year}.json.xz"
    formatted_data = __get_json_data_from_xz(request_link)
    sub_cat_list = __get_cve_file_list(formatted_data)

    for cat in sub_cat_list:
        out = deepcopy(formatted_data)
        out['cve_items'].clear()

        for cve in formatted_data['cve_items']:
            if cat == cve['id'][:11]:
                out['cve_items'].append(cve)
        out['cve_count'] = len(out['cve_items'])

        save_to_json_file(out, f'{cat}xx.json', f"./src/_data/{year}/")
    return formatted_data['cve_count']


def __get_cve_file_list(data) -> list:
    # build the file list
    files = []
    for cve in data['cve_items']:
        files.append(cve['id'][:11])
    return list(set(files))


def save_all_years_json() -> bool:
    """
        Desc:
            This method allows the retrieval (and local save) of all available year CVE datasets from the following repository:
            https://github.com/fkie-cad/nvd-json-data-feeds by fkie-cad
            The data is downloaded in .xz format, extracted and saved to .json in the local /data folder in the format 'CVE-<YEAR>.json'.
        Returns:
            True if the process ends correctly
    """
    cve_count = 0
    for year in range(1999, datetime.now().year + 1):
        try:
            cve_count += save_one_year_json(year)
        except ValueError:
            return False
    save_to_json_file({'cve_count': cve_count}, 'CVE-Count.json')
    build_search_index()
    return True


def get_one_year_json(year: int) -> dict:
    """
        Desc:
            Method to get all the CVEs from the specicied year
        Returns:
            :param year: The reqeusted data year
        Raises:
            :raises FileNotFoundError: if the requested year's folder does not exist
    """
    directory = f"./src/_data/{year}/"
    if not os.path.isdir(directory): # check if 'year' folder exists
        raise FileNotFoundError('Requested year folder not found')

    out = get_json_from_file(f'CVE-{year}-00xx.json', directory)
    out['cve_items'].clear()

    for filename in os.scandir(directory):
        data = get_json_from_file(filename.name, directory)
        out['cve_items'].extend(data['cve_items'])

    out['cve_count'] = len(out['cve_items'])

    return out


def get_one_subcategory_json(cat: str) -> dict:
    tokens = cat.split('-')
    directory = f"./src/_data/{tokens[1]}/"
    if not os.path.isdir(directory): # check if 'year' folder exists
        raise FileNotFoundError('Requested year folder not found')

    return get_json_from_file(f'{cat}xx.json', directory)


def get_one_cve_from_id(cve_id: str, include_quarantined: bool = False) -> dict:
    """
        Desc: 
            Method to retrieve the specified CVE-ID data. It can be specified to include quarantined vulnerabilities (default False),
            which are CVEs awaiting or undergoing analysis and for which it is NOT guaranteed to have available metrics.
            OPTIMIZED: Uses location index for O(1) file lookup instead of scanning entire subcategory files.
        Params:
            :param cve_id: The requested CVE-ID
            :param include_quarantined: Requests the inclusion of quarantined vulnerabilities
        Returns:
            The requested CVE-ID data or empty dict if not found
        Raises:
            :raises ValueError: if the specified CVE-ID is badly formatted
    """
    # Debug: trace entry
    print(f"[NVDHelper] get_one_cve_from_id START: {cve_id}")
    logging.debug(f"get_one_cve_from_id START: {cve_id}")

    if not check_cve(cve_id):
        logging.error(f"Badly formatted CVE-ID: {cve_id}")
        raise ValueError('Badly formatted CVE-ID!')

    # Try to use location index first for O(1) lookup
    try:
        location_index = get_json_from_file("cve_location_index.json", "./src/_data/")
        if cve_id in location_index:
            location = location_index[cve_id]
            year_dir = f"./src/_data/{location['year']}/"
            data = get_json_from_file(location['file'], year_dir)
            
            # Find the specific CVE in the file
            for cve in data['cve_items']:
                if cve['id'] == cve_id:
                    status = cve['vulnStatus']
                    #logging.debug(f"Checking CVE {cve_id} status={status} (via location index)")
                    if status in __ignored_status or (not include_quarantined and (status in __quarantined_status)):
                        print(f"[NVDHelper] get_one_cve_from_id END (ignored status): {cve_id}")
                        logging.debug(f"get_one_cve_from_id END (ignored status): {cve_id}")
                        return {}
                    print(f"[NVDHelper] get_one_cve_from_id FOUND (via location index): {cve_id}")
                    logging.debug(f"get_one_cve_from_id FOUND (via location index): {cve_id}")
                    return cve
    except FileNotFoundError:
        logging.warning("CVE location index not found, falling back to subcategory scan")
    except Exception as e:
        logging.warning(f"Error using location index for {cve_id}: {e}, falling back to subcategory scan")
    
    # Fallback to old method if index not available or CVE not found in index
    print(f"[NVDHelper] get_one_cve_from_id - using fallback subcategory scan for: {cve_id}")
    logging.debug(f"get_one_cve_from_id - using fallback subcategory scan for: {cve_id}")
    data = get_one_subcategory_json(cve_id[:11])
    for cve in data['cve_items']:
        status = cve['vulnStatus']
        # Debug: report status when scanning
        #logging.debug(f"Checking CVE {cve.get('id')} status={status}")
        if status in __ignored_status or (not include_quarantined and (status in __quarantined_status)):
            continue
        if cve['id'] == cve_id:
            print(f"[NVDHelper] get_one_cve_from_id FOUND (via subcategory scan): {cve_id}")
            logging.debug(f"get_one_cve_from_id FOUND (via subcategory scan): {cve_id}")
            return cve

    print(f"[NVDHelper] get_one_cve_from_id END (not found): {cve_id}")
    logging.debug(f"get_one_cve_from_id END (not found): {cve_id}")
    return {}


def get_cves_from_desc(keyword: str, exact_match: bool) -> list:
    """
        Desc:
            Method to retrieve all matching CVEs based on the given keyword.
            The method looks for the keywords in the CVE description and can be of two types:
            - exact_match = False -> every keyword is evaluated individually
            - exact_match = True -> keyword must match exactly
        Params:
            :param keyword: The given keyword to look for
            :param exact_match: The boolean value to specify search mode
        Returns:
            The list of all matching CVEs
    """
    # Debug: trace search invocation
    print(f"[NVDHelper] get_cves_from_desc START keyword='{keyword}' exact_match={exact_match}")
    logging.debug(f"get_cves_from_desc START keyword='{keyword}' exact_match={exact_match}")

    if exact_match:
        result = __get_exact_match(keyword)
    else:
        result = __get_any_match(keyword)

    print(f"[NVDHelper] get_cves_from_desc END found={len(result)} items for keyword='{keyword}'")
    logging.debug(f"get_cves_from_desc END found={len(result)} items for keyword='{keyword}'")
    return result


def __get_exact_match(keyword: str) -> list:
    """
        Finds CVEs that contain any of the words from the keyword.
        Uses the pre-built search index for high performance.
        Uses 10 threads to parallelize CVE retrieval.
    """
    try:
        index = get_json_from_file("cve_search_index.json", "./src/_data/")
    except FileNotFoundError:
        logging.error("Search index 'cve_search_index.json' not found in './src/_data/'.")
        logging.error("Please run build_search_index() first to enable fast searching.")
        return []

    # Split keyword into unique, lowercase words
    keywords = set(keyword.lower().split())
    matching_cve_ids = set()

    print(f"[NVDHelper] __get_exact_match START keywords={keywords}")
    logging.debug(f"__get_exact_match START keywords={keywords}")

    # Collect all unique CVE IDs that match any of the keywords
    for key in keywords:
        # .get(key, []) returns the list of IDs or an empty list if the key is not in the index
        matching_cve_ids.update(index.get(key, []))

    # Convert to list and split work among 4 threads
    cve_ids_list = list(matching_cve_ids)
    print(f"[NVDHelper] __get_exact_match - total matching IDs: {len(cve_ids_list)}")
    logging.debug(f"__get_exact_match - total matching IDs: {len(cve_ids_list)}")
    
    if not cve_ids_list:
        return []
    
    # Parallelize CVE retrieval using ThreadPoolExecutor with 4 workers
    out = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        print(f"[NVDHelper] __get_exact_match - starting ThreadPoolExecutor with 4 workers")
        logging.debug("__get_exact_match - starting ThreadPoolExecutor with 4 workers")

        # Submit all tasks
        future_to_cve = {executor.submit(get_one_cve_from_id, cve_id): cve_id 
                        for cve_id in cve_ids_list}
        
        # Collect results as they complete
        for future in as_completed(future_to_cve):
            cve_id = future_to_cve[future]
            try:
                cve = future.result()
                print(f"[NVDHelper] __get_exact_match - completed {cve_id} (found={bool(cve)})")
                logging.debug(f"__get_exact_match - completed {cve_id} (found={bool(cve)})")
                if cve:  # Filter out empty results
                    out.append(cve)
            except Exception as exc:
                logging.error(f'CVE {cve_id} generated an exception: {exc}')
    
    return out


def __get_any_match(keyword: str) -> list:
    """
        Finds CVEs where the keyword is a substring of any word in the description.
        Uses the pre-built search index for high performance.
        Uses 10 threads to parallelize CVE retrieval.
    """
    try:
        index = get_json_from_file("cve_search_index.json", "./src/_data/")
    except FileNotFoundError:
        logging.error("Search index 'cve_search_index.json' not found in './src/_data/'.")
        logging.error("Please run build_search_index() first to enable fast searching.")
        return []

    search_term = keyword.lower()
    matching_cve_ids = set()

    print(f"[NVDHelper] __get_any_match START search_term='{search_term}'")
    logging.debug(f"__get_any_match START search_term='{search_term}'")

    # Iterate through all keys in the index and check for substring matches
    for key, cve_ids in index.items():
        if search_term in key:
            matching_cve_ids.update(cve_ids)

    # Convert to list for parallel processing
    cve_ids_list = list(matching_cve_ids)
    print(f"[NVDHelper] __get_any_match - total matching IDs: {len(cve_ids_list)}")
    logging.debug(f"__get_any_match - total matching IDs: {len(cve_ids_list)}")
    
    if not cve_ids_list:
        return []
    
    # Parallelize CVE retrieval using ThreadPoolExecutor with 10 workers
    out = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        print(f"[NVDHelper] __get_any_match - starting ThreadPoolExecutor with 10 workers")
        logging.debug("__get_any_match - starting ThreadPoolExecutor with 10 workers")

        # Submit all tasks
        future_to_cve = {executor.submit(get_one_cve_from_id, cve_id): cve_id 
                        for cve_id in cve_ids_list}
        
        # Collect results as they complete
        for future in as_completed(future_to_cve):
            cve_id = future_to_cve[future]
            try:
                cve = future.result()
                print(f"[NVDHelper] __get_any_match - completed {cve_id} (found={bool(cve)})")
                logging.debug(f"__get_any_match - completed {cve_id} (found={bool(cve)})")
                if cve:  # Filter out empty results
                    out.append(cve)
            except Exception as exc:
                logging.error(f'CVE {cve_id} generated an exception: {exc}')
    
    return out


def get_cves_from_cwe(cwe_id: str):
    """
        Desc:
            Method to retrieve all CVEs related to the given CWE-ID.
        Params:
            :param cwe_id: The requested CWE-ID
        Returns:
            The list of all CVEs related to the requeste CWE
        Raises:
            :raises ValueError: if the specified CWE-ID is badly formatted
    """
    if not check_cwe(cwe_id):
        raise ValueError('Badly formatted CWE-ID!')
    out = []
    for year in range(datetime.now().year + 1, 1999, -1):
        result = get_one_year_json(year)
        for cve in result['cve_items']:
            if 'weaknesses' not in cve.keys():
                continue
            for cwe in cve['weaknesses']:
                if ((cwe['description'])[0])['value'] == cwe_id:
                    out.append(cve)
                    break
    return out


def get_cve_count() -> int:
    """
        Desc:
            Method to retrieve the total count of all analyzed CVEs.
        Returns:
            :returns: The total analyzed CVE count
    """
    data = get_json_from_file('CVE-Count.json')
    return data['cve_count']


def build_cve_location_index():
    """
        Desc:
            Builds an index mapping CVE-ID to its file location for O(1) lookup.
            This allows direct file access instead of scanning entire subcategory files.
            The index maps CVE-ID to {file, year}.
    """
    logging.info("Building CVE location index...")
    location_index = {}
    data_dir = "./src/_data/"
    
    for year in range(1999, datetime.now().year + 1):
        year_dir = f"{data_dir}{year}/"
        if not os.path.isdir(year_dir):
            continue
            
        logging.info(f"Indexing locations for year {year}...")
        for filename in os.scandir(year_dir):
            if not filename.name.endswith('.json'):
                continue
                
            try:
                data = get_json_from_file(filename.name, year_dir)
                for cve in data['cve_items']:
                    cve_id = cve['id']
                    location_index[cve_id] = {
                        'file': filename.name,
                        'year': year
                    }
            except Exception as e:
                logging.warning(f"Error indexing {filename.name}: {e}")
                continue
    
    index_path = os.path.join(data_dir, "cve_location_index.json")
    save_to_json_file(location_index, "cve_location_index.json", data_dir)
    logging.info(f"CVE location index built with {len(location_index)} entries and saved to {index_path}")


def build_search_index():
    """
        Desc:
            Builds an inverted index for fast CVE description searches.
            This is a heavy operation and should be run only once or after updates.
            The index maps keywords to a list of CVE IDs.
            Also builds the CVE location index for O(1) file lookup.
    """
    logging.info("Building search index... This may take a while.")
    index = {}
    data_dir = "./src/_data/"
    
    # Regex to find words (alphanumeric)
    word_regex = re.compile(r'\b\w+\b')

    for year in range(1999, datetime.now().year + 1):
        try:
            logging.info(f"Indexing year {year}...")
            # Use get_one_year_json to aggregate all CVEs for the year
            year_data = get_one_year_json(year)
            for cve in year_data['cve_items']:
                cve_id = cve['id']
                # Combine ID and description for indexing
                text_to_index = cve_id + ' ' + cve['descriptions'][0]['value']
                
                # Find all words, convert to lowercase, and add to index
                words = set(word.lower() for word in word_regex.findall(text_to_index))
                
                for word in words:
                    if word not in index:
                        index[word] = []
                    index[word].append(cve_id)
        except FileNotFoundError:
            logging.warning(f"Data for year {year} not found. Skipping.")
            continue
            
    # Save the index to a file
    index_path = os.path.join(data_dir, "cve_search_index.json")
    save_to_json_file(index, "cve_search_index.json", data_dir)
    logging.info(f"Search index built successfully and saved to {index_path}")
    
    # Build location index for fast CVE retrieval
    build_cve_location_index()
