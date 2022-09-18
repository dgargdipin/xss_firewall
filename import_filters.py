import requests
filters_obj=requests.get('https://raw.githubusercontent.com/PHPIDS/PHPIDS/master/lib/IDS/default_filter.json').json()
filters_strings=[a["rule"] for a in filters_obj["filters"]["filter"]]
