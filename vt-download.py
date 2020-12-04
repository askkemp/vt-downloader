#!/usr/bin/python
# Built in Python 3.6
__author__ = "Kemp Langhorne"
__copyright__ = "Copyright (C) 2020 AskKemp.com"
__license__ = "agpl-3.0"
__version__ = "Beta 1.0"

import requests
import bz2 # Files form VT are BZ2 compressed
import json
import logging
from datetime import datetime, timedelta
import pandas as pd # for generating filenames based dates and time
from pathlib import Path
import argparse
import elasticapm
import elasticsearch
import multiprocessing

#
# Setup Configuration here
#

# Where all folders and files will be created
full_path_to_save_output = "/opt/virustotal/"

# VT API key with rights to feeds API
vtapikey = "keyhere" # VT private key with feeds rights

# Elasticsearch index to check for presence of feeds summary data. Index must already exist.
es_index_alias = "virustotal"

# For initial setup, if chosen
es_ilm_policy = "virustotal"
es_template_name = "virustotal"
es_template_roller_alias = "virustotal"
es_template_index_patterns = "virustotal-*"

# Client setup for Elastic APM and Elasticsearch. Set URL, user, pass, certificates, etc.
apm_client = elasticapm.Client(server_timeout = "10s", service_name="VTDownloader", service_node_name="Node_1", server_url="http://127.0.0.1:8200", recording="true", environment="PROD")
es_client = elasticsearch.Elasticsearch(http_auth=("user", "pwd"), hosts=['127.0.0.1'], timeout=80)


# Logging
logger = logging.getLogger()
logger.setLevel(logging.INFO) # DEBUG is all the data

requests_logger = logging.getLogger('elasticsearch')
requests_logger.setLevel(logging.WARN)

@elasticapm.capture_span()
def generate_filenames(num_days_ago):
    """
    The various VT feeds API allow pulling historic data back to 7 days. This code generates all possible 
    filesnames for 7 days in the format that the VT feeds API expects. In its own function so that 
    the same set of datetimes can be given to different APIs or other functions.

    Args:
        num_days_ago (int)

    Returns:
        type list of str that are datetimes as filenames. e.g ['202011150019', '202011150020']
    """

    # Dates
    datetime_now = datetime.now()
    datetime_past = datetime_now - timedelta(days=num_days_ago) 
    vt_date_now = datetime_now.strftime("%Y%m%d%H%M") # VT feeds APIs requires YYYYMMDDhhmm
    vt_date_past = datetime_past.strftime("%Y%m%d%H%M") # VT feeds APIs allows only 7 days back.

    filenames_to_process = (pd.DataFrame(columns=['NULL'],
                      index=pd.date_range(vt_date_past, vt_date_now, freq='1T')) # T is minutely frequency
           .index.strftime('%Y%m%d%H%M') # eg 202011150019. Exactly as the API wants it
           .tolist()
    )
    logger.info('Starting from {} days ago, there are {} filenames to process. First file {}. Last file: {}'.format(num_days_ago, len(filenames_to_process), filenames_to_process[0], filenames_to_process[-1]))
    return filenames_to_process

@elasticapm.capture_span()
def determine_api_type(absolutepath):
    """
    Given a pathlib object, first check if truely absolutepath, then convert to string and based on folder names 
    determine API used to generate that file

    Args:
      absolutepath (object): Pathlib PosixPath e.g. /opt/virustotal/files/2020-11-17/202011172354

    Return
        api_type (str)
    """

    try:
        # use string in file path to determine api type
        absolutepath_str = str(absolutepath)
        if "/files/" in absolutepath_str:
            api_type = "files"
        elif "/urls/" in absolutepath_str:
            api_type = "urls"
        elif "/filebehaviours/" in absolutepath_str:
            api_type = "filebehaviours"
        else:

            raise Exception("Cannot determine API type exiting")
    except Exception as e:
        logging.error(e)
        apm_client.capture_exception()

    return api_type

@elasticapm.capture_span()
def is_summaryfile_in_elasticsearch(absolutepath):
    """
    Given a pathlib absolutepath, build query and check Elasticsearch for presence of summary file

    Args:
      absolutepath (object): Pathlib PosixPath e.g. /opt/virustotal/files/2020-11-17/202011172354

    Return
      False: Summary file not present in Elasticsearch index
      True: Summary file IS presente in Elasticsearch index
    """

    apm_client.begin_transaction(transaction_type="elasticsearch")

    if not absolutepath.is_absolute:
        try:
            apm_client.end_transaction("elasticsearch", "failure")
            raise Exception('[is_summaryfile_in_elasticsearch] not absolute path')
        except Exception as e:
            logger.warning(e)
            apm_client.capture_exception()

    api_type = determine_api_type(absolutepath)

    # Build ES search body containing the VT api type and the file name
    es_query = api_type + " AND " + absolutepath.name
    search_dict = {
      "query": {
        "query_string": {
          "fields": [ "log.file.path" ],
          "query": es_query
        }
      }
    }
    output = es_client.count(index=es_index_alias, body=search_dict)
    apm_client.end_transaction("elasticsearch", "success")
    if output['count'] ==0: # A count of 0 means it is not in the Elasticsearch index
        return False
    elif output['count'] > 1: # This could possible set much higher
        return True
    else:
        try:
            raise Exception('[is_summaryfile_in_elasticsearch] something wrong')
        except Exception as e:
            logger.warning(e)
            apm_client.capture_exception()

@elasticapm.capture_span()
def create_summary(absolutepath, output_base_directory):
    """
    Given a filepath to a raw file, create a .summary file if it does not exist. Saved files are text (json).

    Args:
        absolutepath (object): Pathlib PosixPath to a raw file on disk which was downloaded by VT API e.g. /opt/virustotal/files/2020-11-17/202011172354
        output_base_directory (str): full path where output is stored. A summary folder will be created in this path.

    Returns:
        None
    """

    #logging.info("[create_summary] Starting create summary process")
    apm_client.begin_transaction(transaction_type="CreateSummary")

    api_type = determine_api_type(absolutepath=absolutepath)

    # Check if file exists which means this process already occured on it.
    if not absolutepath.is_file(): # file exists
        try:
            raise Exception("[create_summary] Input file missing: {} ".format(absolutepath))
        except Exception as e:
            logging.warning(e)
            apm_client.capture_exception()

    # Folder and file setup
    base_folder_str = output_base_directory + "summary/" + api_type + "/"
    temp_folder_str = base_folder_str + "temp/"

    summary_file_str = base_folder_str + absolutepath.name + '.summary'
    summary_file = Path(summary_file_str)

    # To prevent a possible race condition where Logstash reads and deletes the file before it is finished writting,
    # create the summary file in a temp folder then move it once writting is complete
    # This file gets moved at the end of this function
    summary_file_temp_str = temp_folder_str + absolutepath.name + '.summary'
    summary_file_temp = Path(summary_file_temp_str)

    # Create folder, if missing
    Path(temp_folder_str).mkdir(parents=True, exist_ok=True)

    # Check if file exists which means this process already occured on it.
    if summary_file.is_file(): # file exists
        logging.info("[create_summary] Summary file already exists: {} ".format(summary_file))
        apm_client.end_transaction("CreateSummary", "AlreadyExists")
        return

    else: # File does not exist. Create new file that matches input filename append .summary
        logging.info("[create_summary] Creating summary file: {}".format(summary_file))
        with open(summary_file_temp, 'wb') as output_vtsummary:
            with bz2.open(absolutepath, 'r') as input_file:
                output_dict = {}
                for i, line in enumerate(input_file):

                    data = json.loads(line)
                    output_dict = {}
                    output_dict['vt'] = {}
                    output_dict['vt']['type'] = data.get('type')

                    attributes = data.get('attributes')

                    #
                    # Specific to files API
                    #
                    all_found_urls_list = [] # holds all URLs found in data for files feed
                    if attributes.get('md5'):
                        output_dict['hash'] = {}
                        output_dict['hash']['md5'] = attributes.get('md5')
                        output_dict['hash']['sha1'] = attributes.get('sha1')
                        output_dict['hash']['sha256'] = attributes.get('sha256')
                        output_dict['vt']['filenames'] = attributes.get('names') # type list
                    if attributes.get('androguard'):
                        if attributes.get('androguard').get('StringsInformation'):
                            strings_info = attributes.get('androguard').get('StringsInformation')
                            for string in strings_info:
                                if (string.startswith('http://') or string.startswith('https://')) and not (string == 'http://' or string == 'https://'):
                                    all_found_urls_list.append(string)

                    if data.get('relationships'):
                        if data.get('relationships').get('contacted_urls'):
                            if data.get('relationships').get('contacted_urls').get('data'):
                                for url in data.get('relationships').get('contacted_urls').get('data'):
                                    if url.get('context_attributes'):
                                        if url.get('context_attributes').get('url'):
                                            all_found_urls_list.append(url.get('context_attributes').get('url'))

                        if data.get('relationships').get('embedded_urls'):
                            if data.get('relationships').get('embedded_urls').get('data'):
                                for url in data.get('relationships').get('embedded_urls').get('data'):
                                    if url.get('context_attributes'):
                                        if url.get('context_attributes').get('url'):
                                            all_found_urls_list.append(url.get('context_attributes').get('url'))

                    if attributes.get('network_infrastructure'):
                        for aurl in attributes.get('network_infrastructure'):
                            all_found_urls_list.append(aurl)

                    # Whitelist process to remove unuseful URLs from summary file output
                    url_whitelist_startswith = ['http://go.microsoft.com', 'http://www.microsoft.com',\
                       'http://www.download.windowsupdate.com', 'http://swupmf.adobe.com',\
                       'http://www.googleadservices.com', 'http://www.gstatic.com/',\
                       'http://crl.microsoft.com', 'http://www.google.com',\
                       'http://cacerts.digicert.com', 'http://schemas.android.com/',\
                       'http://www.facebook.com', 'http://www.w3.org/',\
                       'https://pagead2.googlesyndication.com', 'https://plus.google.com/',\
                       'https://www.googleapis.com/', 'https://www.google.com',\
                       'https://facebook.com', 'https://csi.gstatic.com', 'http://ns.adobe.com',\
                       'https://www.googleapis.com', 'http://purl.org', 'https://googleads.g.doubleclick.net',\
                       'http://plus.google.com/', 'http://crt.usertrust.com', 'https://www.googleapis.com/',\
                       'http://schemas.microsoft.com', 'http://schemas.android.com', 'http://crl.sectigo.com',\
                       'http://crl.comodo.', 'http://crl.thawte.com', 'http://crl4.digicert.com',\
                       'http://ts-crl.ws.symantec.com', 'http://crl.comodoca.com', 'http://crl.verisign.com/',\
                       'http://crl3.digicert.com', 'http://crl.globalsign.com', 'http://crl.usertrust.com',\
                       'http://csc3-2004-crl.verisign.com', 'http://crl.comodoca.com', 'http://crl.verisign.com/',\
                       'http://schemas.openxmlformats.org', 'https://www.google.com', 'http://crl.globalsign.net',\
                       'http://csc3-2010-crl.verisign.com', 'http://s1.symcb.com', 'http://s.symcb.com',\
                       'http://crl.godaddy.com', 'http://crl.netsolssl.com', 'http://addons.mozilla.org/',\
                       'http://sv.symcb.com/', 'http://csc3-2009-2-crl.verisign.com', 'http://crl.trust-provider.com',\
                       'http://www.certplus.com', 'http://pki-crl.symauth.com', '"http://crl.trust-provider.com',\
                       'http://t1.symcb.com', 'http://tl.symcb.com', 'http://csc3-2009-crl.verisign.com',\
                       'http://cert.startcom.org', 'http://cs-g2-crl.thawte.com', 'http://crl.startcom.org',\
                       'http://sw.symcb.com', 'http://sf.symcb.com/', 'http://evcs-crl.ws.symantec.com',\
                       'http://crl.geotrust.com', 'http://crl.entrust.net', 'http://certificates.intel.com',\
                       'http://crl.apple.com', 'http://crl.certum.pl', 'http://certificates.godaddy.com',\
                       'http://status.verisign.com', 'http://crl.xrampsecurity.com', 'http://crl.startssl.com',\
                       'http://sc.symcb.com/', 'http://rb.symcb.com/', 'http://crt.sectigo.com/', 'https://sectigo.com',\
                       'http://www.google-analytics.com', 'https://support.google.com', 'https://.facebook.com',\
                       'http://xmlpull.org', 'http://ts-aia.ws.symantec.com', 'https://ssl.google-analytics.com',\
                       'http://play.google.com', 'https://google.com', 'https://www.digicert.com', 'https://d.symcb.com',\
                       'https://www.googletagmanager.com', 'https://dc.services.visualstudio.com',\
                       'http://csc3-2010-aia.verisign.com', 'https://www.facebook.com', 'http://www.digicert.com',\
                       'https://twitter.com', 'http://www.android.com/', 'http://logo.verisign.com', 'https://www.verisign.com',\
                       'http://ocsp2.globalsign.com', 'http://crt.sectigo.com', 'https://www.linkedin.com',\
                       'http://crl.starfieldtech.com', 'http://crl.quovadisglobal.com', 'http://th.symcb.com/',\
                       'http://crls1.wosign.com', 'http://www.apple.com', 'http://www.globaltrustfinder.com',\
                       'http://www.entrust.net', 'http://www.ascertia.com', 'http://subca.crl.certum.pl',\
                       'http://sslcom.crl.certum.pl', 'http://mscrl.microsoft.com', 'http://crls.ssl.com/',\
                       'http://crl.rootca1.amazontrust.com/', 'http://crt.comodoca.com', 'https://play.google.com/',\
                       'http://www.apache.org', 'https://www.globalsign.com', 'https://play.google.com', 'https://www.paypal.com',
                       'http://google.com', 'http://market.android.com', 'http://googleads.g.doubleclick.net',\
                       'https://graph.facebook.com/', 'http://m.facebook.com', 'http://xml.org', 'https://www.thawte.com/',\
                       'http://secure.globalsign.com/', 'http://schemas.xmlsoap.org', 'http://schema.org',\
                       'http://api.airpush.com', 'http://ocsp.godaddy.com/', 'http://jquery.com',\
                       'https://www.google-analytics.com', 'https://api.airpush.com', 'http://csc3-2004-aia.verisign.com/',\
                       'https://market.android.com', 'https://www.youtube.com', 'https://m.facebook.com',\
                       'https://archive.org', 'http://apache.org', 'https://github.com', 'https://developer.apple.com/',\
                       'https://www.googleadservices.com', 'http://maps.google.com', 'https://www.amazon.com',\
                       'https://msh.amazon.co', 'https://api.amazon.', 'http://twitter.com', 'http://www.videolan.org',\
                       'https://firebase.google.com', 'https://ieonline.microsoft.com', 'http://jquery.org',\
                       'http://developer.android.com', 'https://ajax.googleapis.com', 'https://m.google.com', 'http://www.youtube.com/',\
                       'https://upload.youtube.com', 'https://test-youtubei.sandbox.googleapis.com',\
                       'https://fls-na.amazon.com', 'https://oneclient.sfx.ms', 'http://www.amazon.ca',\
                       'http://www.amazon.cn', 'http://www.amazon.co', 'https://na.account.amazon.com' ,\
                       'http://www.idpf.org', 'https://stg-api.di.atlas.samsung.com', 'https://www.baidu.com/',\
                       'https://youtubei.googleapis.com', 'https://secure.comodo.net', 'https://apis.google.com',\
                       'https://forum.videolan.org', 'https://graph.facebook.com', 'http://www.bing.com',\
                       'https://www.videolan.org', 'http://lba.baidu.com', 'https://imasdk.googleapis.com',\
                       'https://m.baidu.com', 'https://fonts.googleapis.com', 'http://www.example.com',\
                       'https://app-measurement.com', 'http://checkip.amazonaws.com', 'http://example.com',\
                       'https://cn-ms.samsungapps.com', 'https://vas.samsungapps.com', 'http://www.gnu.org',\
                       'http://iptc.org'
                    ]

                    #
                    # Specific to urls API
                    #
                    if attributes.get('url'):
                        output_dict['vt']['last_final_url'] = attributes.get('last_final_url')
                        output_dict['vt']['url'] = attributes.get('url')
                        if attributes.get('outgoing_links'): # list
                            for aurl in attributes.get('outgoing_links'):
                                all_found_urls_list.append
                        if attributes.get('favicon'):
                            if attributes.get('favicon').get('raw_md5'):
                                if not output_dict.get('hash'):
                                    output_dict['hash'] = {}
                                output_dict['hash']['md5_favicon'] = attributes.get('favicon').get('raw_md5')

                    pruned_urls_list = [x for x in all_found_urls_list if not any(x.startswith(y) for y in url_whitelist_startswith)]

                    if pruned_urls_list:
                        output_dict['vt']['related_urls'] = pruned_urls_list

                    # General feeds API
                    output_dict['vt']['tags'] = attributes.get('tags') # type list
                    output_dict['vt']['submission_date'] = attributes.get('last_submission_date')
                    #output_dict['vt']['submission_ISO8601'] = datetime.utcfromtimestamp(attributes.get('last_submission_date')).isoformat() + 'Z'
                    if data.get('context_attributes'):
                        if data.get('context_attributes').get('submitter'):
                            submitterdata = data.get('context_attributes').get('submitter')
                            output_dict['geo'] = {}
                            output_dict['geo']['city'] = submitterdata.get('city')
                            output_dict['geo']['country'] = submitterdata.get('country')
                            output_dict['geo']['region'] = submitterdata.get('region')
                            output_dict['vt']['submitter_id'] = submitterdata.get('id')
                            output_dict['vt']['interface'] = submitterdata.get('interface')

                    output_vtsummary.write(json.dumps(output_dict).encode() + "\n".encode())
                    apm_client.end_transaction("CreateSummary", "created")

        # put summary file into final resting spot
        summary_file_temp.rename(summary_file)

    return

@elasticapm.capture_span()
def vt_download(list_of_filenames, output_base_directory, api_type):
    """
    Given a list of filenames, checks if file is on disk and if not conducts download via VT API
    API: You can download files up to 7 days old, and the most recent batch has always a 60 minutes lag with respect with to the current time.

    Args:
        list_of_filenames (list): a list of filenames as excepted by the VT API. e.g. 202011172354
        output_base_directory (str): where the files will be saved
        api_type (str): Can be one of: files, filebehaviours, urls

    Returns:
        Dict of absolute path to files downloaded with keys success. Keys failure and ignored contain only filename (no path).
    """

    # VT API Endpoints and output folders
    if api_type == "files":
        vt_apiendpoint = "https://www.virustotal.com/api/v3/feeds/files/{time}"
        type_folder = "files/"
    elif api_type == "filebehaviours":
        vt_apiendpoint = "https://www.virustotal.com/api/v3/feeds/file-behaviours/{time}"
        type_folder = "filebehaviours/"
    elif api_type == "urls":
        vt_apiendpoint = "https://www.virustotal.com/api/v3/feeds/urls/{time}"
        type_folder = "urls/"
    else:
        try:
            raise Exception("API type specififed by user is not found")
        except Exception as e:
            logging.error(e)
            apm_client.capture_exception()

    logging.info("Downloading using VirusTotal {} feeds API".format(api_type))

    # Counts used in logging
    download_failure_list = [] # list of ones that failed when downloaded
    download_success_list = [] # list of ones that failed when downloaded
    ignored_list = [] # list of what was not downloaded due to filename already being present on disk


    # Go through list of all filenames provided by pandas code to see if it already exists
    # and it if does not exist, then download it from the VT api

    for filename in list_of_filenames:
        apm_client.begin_transaction(transaction_type="VT_Download")
        # Extract YYYY-MM-DD from filename like 202011201455 for on-disk folder creation 
        folder_year = filename[:4] # 2020
        folder_month = filename[4:6] # 11
        folder_day = filename[6:8] # 20
        folder_ym = folder_year + "-" + folder_month + "-" + folder_day + "/"
        combined_output_folder = output_base_directory + type_folder + folder_ym
        absolute_filepath = combined_output_folder + filename

        # Convert to pathlib.PosixPath
        absolute_filepath = Path(absolute_filepath)

        # Create folders, if missing
        Path(combined_output_folder).mkdir(parents=True, exist_ok=True)

        # If file exists then it is already downloaded. If doesnt exist, then download.
        if absolute_filepath.is_file():
            ignored_list.append(absolute_filepath)
            apm_client.end_transaction("VT_Download", "file_already_exists")
            continue
        else:
            response = requests.get(
                vt_apiendpoint.format(time=filename),
                headers={'x-apikey': vtapikey})

            if response.status_code != 200: # https://developers.virustotal.com/v3.0/reference#errors
                apm_client.end_transaction("VT_Download", "failure")

                try: 
                    response_bad = response.json()
                    download_failure_list.append(absolute_filepath)
                except ValueError: # this should never fail
                    logger.error("API: {} Filedate: {} HTTP: {} Message: {}".format(api_type, filename, response.status_code, response.text))
                    apm_client.capture_exception()

                if response_bad.get("error"):
                    if response_bad.get("error").get("message"):
                        logger.error("API: {} Filedate: {} HTTP: {} Message: {}".format(api_type, filename, response.status_code, response_bad.get("error").get("message")))
            else:
                with absolute_filepath.open('wb') as f:
                    f.write(response.content)
                download_success_list.append(absolute_filepath)
                apm_client.end_transaction("VT_Download", "downloaded")

    logging.info("With VT API {}, failed to download: {} files".format(api_type, len(download_failure_list)))
    #logging.info(download_failure_list)
    logging.info("With VT API {}, successfully downloaded: {} files".format(api_type, len(download_success_list)))
    logging.info("With VT API {}, ignored the download of: {} files".format(api_type, len(ignored_list)))

    # Build output to return
    return_outout = {}
    return_outout['success'] = download_success_list
    return_outout['failure'] = download_failure_list
    return_outout['ignored'] = ignored_list

    return return_outout

def elasticsearch_setup():
    """
    Creates ElasticSearch index template, the ILM policy, and bootstraps the index.
    Will first check if each exists and will not overwrite.
    index_template and bootstrap contain variables set in config at top of script.
    """

    index_template = {'order': 0,
 'index_patterns': [es_template_index_patterns],
 'settings': {'index': {'lifecycle': {'name': 'test_virustotal',
    'rollover_alias': es_template_roller_alias},
   'codec': 'best_compression',
   'mapping': {'total_fields': {'limit': '10000'}},
   'refresh_interval': '5s',
   'number_of_shards': '2'}},
 'aliases': {},
 'mappings': {'properties': {'geo': {'type': 'object',
    'properties': {'country': {'type': 'keyword'},
     'city': {'type': 'keyword'},
     'region': {'type': 'keyword'}}},
   'log': {'type': 'object',
    'properties': {'path': {'type': 'keyword'}, 'file': {'type': 'object'}}},
   'hash': {'type': 'object',
    'properties': {'sha1': {'type': 'keyword'},
     'sha256': {'type': 'keyword'},
     'md5': {'type': 'keyword'},
     'md5_favicon': {'type': 'keyword'}}},
   'vt': {'type': 'object',
    'properties': {'submission_date': {'format': 'epoch_second',
      'index': True,
      'ignore_malformed': False,
      'store': False,
      'type': 'date',
      'doc_values': True},
     'filenames': {'type': 'text', 'fields': {'keyword': {'type': 'keyword'}}},
     'submitter_id': {'type': 'keyword'},
     'last_final_url': {'eager_global_ordinals': False,
      'index_phrases': False,
      'fielddata': False,
      'norms': True,
      'index': True,
      'store': False,
      'type': 'text',
      'fields': {'keyword': {'eager_global_ordinals': False,
        'norms': False,
        'ignore_above': 8191,
        'index': True,
        'store': False,
        'type': 'keyword',
        'split_queries_on_whitespace': False,
        'index_options': 'docs',
        'doc_values': True}},
      'index_options': 'positions'},
     'related_urls': {'type': 'text',
      'fields': {'keyword': {'type': 'keyword'}}},
     'interface': {'type': 'keyword'},
     'type': {'type': 'keyword'},
     'url': {'type': 'text',
      'fields': {'keyword': {'eager_global_ordinals': False,
        'norms': False,
        'ignore_above': 8191,
        'index': True,
        'store': False,
        'type': 'keyword',
        'split_queries_on_whitespace': False,
        'index_options': 'docs',
        'doc_values': True}}},
     'tags': {'type': 'keyword'}}}}}}

    ilm_policy = {'policy': {'phases': {'hot': {'min_age': '0ms',
    'actions': {'rollover': {'max_size': '10gb', 'max_age': '30d'},
     'set_priority': {'priority': 100}}}}}}

    bootstrap = {'aliases': {es_index_alias: {'is_write_index': True}}}

    # Load Index Lifecycle Policies
    try:
        es_client.ilm.get_lifecycle(policy=es_ilm_policy)
        logger.info("ElasticSearch index lifecycle policy {} already exists. Taking no action.".format(es_ilm_policy))
    except elasticsearch.NotFoundError: # ilm policy not found
        logger.info("ElasticSearch index lifecycle policy not found. Creating ILM policy: {}".format(es_ilm_policy))
        es_client.ilm.put_lifecycle(es_ilm_policy, body=ilm_policy)

    # Load index template
    if not es_client.indices.exists_template(es_template_name):
        logger.info("ElasticSearch index template not found. Creating index template: {}".format(es_template_name))
        es_client.indices.put_template(es_template_name, index_template)
    else:
        logger.info("ElasticSearch index template {} already exists. Taking no action.".format(es_template_name))

    # Bootstrap index, if needed
    datetime_now = datetime.now()
    datetime_now = datetime_now.strftime("%Y.%m.%d")
    index_name = es_template_index_patterns[:-1] + datetime_now + "-000001" # e.g. virustotal-2020.12.02-000001
    if not es_client.indices.exists(index=index_name):
        logger.info("ElasticSearch index not found. Creating index: {}".format(index_name))
        es_client.indices.create(index=index_name, body=bootstrap)
    else:
        logger.info("ElasticSearch index {} found. taking no action".format(index_name))


def multiprocess_summary(absolutepath):
    """Checks if summary file is in Elastic search then generates summary file if not present"""
    if is_summaryfile_in_elasticsearch(absolutepath=absolutepath) == False:
        create_summary(absolutepath=absolutepath, output_base_directory=full_path_to_save_output)

def main():

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description='\
Overview: Downloads files from VT feeds API and saves it to disk. If desired, creates a small summary file. Integrates with ElasticSearch and Elastic APM.\n\
\n\
Configuration Requirement:\n\
    Edit the top of this Python script to include the VT API key, Elasticsearch credentials, Elastic APM credentials, and output folder.\n\
\n\
Examples:\n\
    Download from VT the URL feed starting from 7 days ago and create summaries:\n\
        $ %(prog)s --download-feed urls --num-days-ago 7 --create-summaries True\n\
\n\
    Look across all previously downloaded URLS files on disk and create summaries for them:\n\
        $ %(prog)s --back-populate-summaries urls\n\
\n\
    Create a single summary file based on an input of a previously downloaded file:\n\
        $ %(prog)s --create-summaries /opt/virustotal/urls/2020-11-28/202011280908\n\
\n\
')


    groupA = parser.add_argument_group("VirusTotal Feed Download and Processing Options")
    groupA.add_argument('--download-feed',
                        required=False,
                        dest='vt_api',
                        choices=['files', 'urls'],
                        help='Pick the VT feed to download. For the number of days ago provided value, the script will first check if the file is already present. If so, it does NOT download it again and will continue and download the next file.')

    groupA.add_argument('--num-days-ago',
                        action='store',
                        required=False,
                        type=int,
                        dest='num_days_ago',
                        metavar='<1-7>',
                        help='The number of days to start behind the current time. VT allows a max of 7 days.')

    groupA.add_argument('--create-summaries',
                        nargs='?',
                        required=False,
                        type=bool, 
                        dest='create_summaries',
                        metavar='True or False',
                        help='For each file just downloaded from VT, generate a summary file if that file is not present in the Elasticsearch index')

    groupB = parser.add_argument_group("Additional capabilities of this script")
    groupB.add_argument('--back-populate-summaries',
                        nargs='?',
                        required=False,
                        dest='back_populate',
                        choices=['files', 'urls'],
                        help='Finds all downloaded VT feed BZ2 files on disk and determines if there is a matching summary file in the Elasticsearch index. If it is not found in the Elasticsearch index, it generates a summary file.')

    groupB.add_argument('--create-single-summary',
                        action='store',
                        required=False,
                        dest='create_single_summary',
                        metavar='<File Path>',
                        help='Provide an absolute path to VT feed BZ2 file and it will generate a summary file.')

    groupB.add_argument('--setup-elasticsearch',
                        action='store',
                        required=False,
                        type=bool, 
                        dest='setup_elasticsearch',
                        metavar='True or False',
                        help='Creates ElasticSearch index template, the ILM policy, and bootstraps the index. Will not overwrite existing. Must run this before using the rest of the script.')

    args = parser.parse_args()

    if args.vt_api and not (args.num_days_ago or args.create_summaries):
        parser.error("--download-feed requires --num-days-ago and --create-summaries")

    if (args.vt_api or args.num_days_ago or args.create_summaries) and (args.back_populate or args.create_single_summary):
        parser.error("Bad argument combination. See --help.")

    logging.info("Script started: {}".format(datetime.now()))

    # Initial ElasticSearch setup
    if args.setup_elasticsearch:
        elasticsearch_setup()

    # Single summary creation
    if args.create_single_summary:
        create_summary(absolutepath=Path(args.create_single_summary), output_base_directory=full_path_to_save_output)

    # Download process
    if args.vt_api:
        filenames = generate_filenames(num_days_ago=args.num_days_ago)
        vt_returned = vt_download(list_of_filenames=filenames, output_base_directory=full_path_to_save_output, api_type=args.vt_api) # dict of lists
        files_on_disk = vt_returned['success'] # list of pathlib.PosixPath

    if args.back_populate:
        # back populate method
        files_gen = Path(full_path_to_save_output + args.back_populate + '/').glob('**/*[!summary]') # generator object
        files_on_disk = [x for x in files_gen if x.is_file()] # list of pathlib.PosixPath

    # multiprocessor generate summaries
    if (args.vt_api and args.create_summaries) or args.back_populate:

        # Ensure elasticsearch index exists before continuing
        if not es_client.indices.exists(index=es_index_alias):
            raise Exception("The provided Elasticsearch index {} does not exist. Exiting.".format(es_index_alias))
        logging.info("Using {} CPUs to generate {} summary files".format(multiprocessing.cpu_count(), len(files_on_disk)))
        pool = multiprocessing.Pool()
        pool.map(multiprocess_summary, files_on_disk)

    logging.info("Script finished: {}".format(datetime.now()))

if __name__ == "__main__":
    main()
