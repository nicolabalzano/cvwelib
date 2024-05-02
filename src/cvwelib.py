from flask import Flask, request, abort
from flask_cors import CORS, cross_origin
from datetime import datetime
import sys
sys.path.append('src')
import logging
import nvdlib.NVDHelper as nh
import atexit
from apscheduler.schedulers.background import BackgroundScheduler


__scheduler = BackgroundScheduler()
__scheduler.add_job(func=nh.check_for_updates, trigger="cron", hour=0, minute = 30)
__scheduler.start()

def __init_app():
    """Initialize the core application."""
    __app = Flask(__name__, instance_relative_config=False)

    with __app.app_context():
        # before_first_request
        logging.debug('Server starting up...')
        if nh.start_up_server(debug=True):
            logging.debug('Server ready.')
    
        return __app
    

__app = __init_app()
__cors = CORS(__app)
__app.config['CORS_HEADERS'] = 'Content-Type'
__default_port = 8080


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
            return nh.get_one_cve(args[arg] if args[arg] != "" else abort(400))
        if arg == 'year':
            return nh.get_one_year_json(args[arg] if args[arg] != "" else abort(400))
        

# App start up
if __name__ == "__main__":
    __app.run(port=__default_port)

# Shut down the scheduler when exiting the app
atexit.register(lambda: __scheduler.shutdown())