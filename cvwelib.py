from flask import Flask, request, abort
from flask_cors import CORS, cross_origin
import sys
sys.path.append('src')
import os
from utils.Utils import check_cve, check_cwe
import logging
import src.nvdlib.NVDHelper as nh
import cwelib.CWEHelper as ch
import atexit
import os

from apscheduler.schedulers.background import BackgroundScheduler


__scheduler = BackgroundScheduler()
__scheduler.add_job(func=nh.check_for_updates, trigger="cron", hour=0, minute = 30)
__scheduler.add_job(func=ch.update_data, trigger='cron', day='1st Sat', hour=0, minute=30)
__scheduler.start()

def __init_app():
    """Initialize the core application."""
    __app = Flask(__name__, instance_relative_config=False)

    with __app.app_context():
        # before_first_request
        logging.debug('Server starting up...')
        if nh.start_up_server(debug=False) and ch.start_up_server(debug=False):
            logging.debug('Server ready.')
    
        return __app
    

__app = __init_app()
__cors = CORS(__app)
__app.config['CORS_HEADERS'] = 'Content-Type'
__default_port = 5001


@__app.route('/api/get_cve', methods = ['GET'])
@cross_origin()
def get_cve():
    args = request.args.to_dict()
    logging.debug(args)

    if len(args) == 0:
        abort(403)
    
    # Call requested end-point result
    for arg in args:
        if arg == 'cveId':
            return __cve_from_id(args[arg], True if 'includeQuarantined' in args.keys() else False)
        if arg == 'cweId':
            return __cve_from_cwe(args[arg])
        if arg == 'year':
            return __cves_from_year(args[arg])
        if arg == 'keywordSearch':
            return __cves_from_desc(args[arg], True if 'keywordExactMatch' in args.keys() else False)
        if arg == 'cveCount':
            return __cve_count()
    
    abort(400) # No matching function found   


def __cve_from_id(cve_id: str, include_quarantined: bool) -> dict:
    return nh.get_one_cve_from_id(cve_id if check_cve(cve_id) else abort(400), include_quarantined)


def __cve_from_cwe(cwe_id: str) -> dict:
    return nh.get_cves_from_cwe(cwe_id if check_cwe(cwe_id) else abort(400))


def __cves_from_year(year: str) -> dict:
    return nh.get_one_year_json(year if year.strip() != "" else abort(400))


def __cves_from_desc(keyword: str, exact_match: bool) -> dict:
    return nh.get_cves_from_desc(keyword if keyword.strip() != "" else abort(400), exact_match)


def __cve_count() -> dict:
    return {'cveCount': nh.get_cve_count()}


@__app.route('/api/get_cwe', methods = ['GET'])
@cross_origin()
def get_cwe():
    args = request.args.to_dict()
    logging.debug(args)

    if len(args) == 0:
        abort(403)
    
    # Call requested end-point result
    for arg in args:
        if arg == 'all':
            return ch.get_all_cwes()
        if arg == 'cweId':
            return __cwe_from_id(args[arg])
        if arg == 'getParents':
            return __cwe_parents(args[arg])
        if arg == 'getChildren':
            return __cwe_children(args[arg])
        if arg == 'cweCount':
            return __cwe_count()
    
    abort(400) # No matching function found


def __cwe_from_id(cwe_id: str) -> dict:
    return ch.get_cwe_from_id(cwe_id if check_cwe(cwe_id) else abort(400))


def __cwe_parents(cwe_id: str) -> dict:
    return ch.get_cwe_parents(cwe_id if check_cwe(cwe_id) else abort(400))


def __cwe_children(cwe_id: str) -> dict:
    return ch.get_cwe_children(cwe_id if check_cwe(cwe_id) else abort(400))


def __cwe_count() -> dict:
    return {'cweCount': ch.get_cwe_count()}


# App start up
if __name__ == "__main__":
    port = int(os.environ.get('PORT', __default_port))
    __app.run(host = '0.0.0.0', port = port, debug = True)

# Shut down the scheduler when exiting the app
atexit.register(lambda: __scheduler.shutdown())
