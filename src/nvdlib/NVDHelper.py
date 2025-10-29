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

__ignored_status = ['Rejected', 'Received']
__quarantined_status = ['Undergoing Analysis', 'Awaiting Analysis']


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
        Params:
            :param cve_id: The requested CVE-ID
            :param include_quarantined: Requests the inclusion of quarantined vulnerabilities
        Returns:
            The requested CVE-ID data or empty dict if not found
        Raises:
            :raises ValueError: if the specified CVE-ID is badly formatted
    """
    if not check_cve(cve_id):
        raise ValueError('Badly formatted CVE-ID!')
    data = get_one_subcategory_json(cve_id[:11])
    for cve in data['cve_items']:
        status = cve['vulnStatus']
        if status in __ignored_status or (not include_quarantined and (status in __quarantined_status)):
            continue
        if cve['id'] == cve_id:
            return cve
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
    if exact_match:
        return __get_exact_match(keyword)
    else:
        return __get_any_match(keyword)


def __get_exact_match(keyword: str) -> list:
    """
        Finds CVEs where the keyword appears as an exact phrase in the description.
        Uses the fast index search to narrow down candidates, then performs a final check.
    """
    # Use the fast 'any match' to get all potential candidates
    candidates = __get_any_match(keyword)
    
    # Filter the candidates for an exact phrase match
    # We check the lowercase description for the lowercase keyword
    keyword_lower = keyword.lower()
    exact_matches = [
        cve for cve in candidates 
        if keyword_lower in cve['descriptions'][0]['value'].lower()
    ]
    
    return exact_matches


def __get_any_match(keyword: str) -> list:
    """
        Finds CVEs that contain any of the words from the keyword.
        Uses the pre-built search index for high performance.
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

    # Collect all unique CVE IDs that match any of the keywords
    for key in keywords:
        # .get(key, []) returns the list of IDs or an empty list if the key is not in the index
        matching_cve_ids.update(index.get(key, []))

    # Retrieve the full CVE data for each unique ID found
    # Using a list comprehension for a more concise syntax
    out = [get_one_cve_from_id(cve_id) for cve_id in matching_cve_ids]
    
    # Filter out any potential empty results (e.g., if a CVE_ID was in the index but the file is missing)
    return [cve for cve in out if cve]


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


def build_search_index():
    """
        Desc:
            Builds an inverted index for fast CVE description searches.
            This is a heavy operation and should be run only once or after updates.
            The index maps keywords to a list of CVE IDs.
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
