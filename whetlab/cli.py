import os, sys, select
import ConfigParser
import click, requests, whetlab
from tabulate import tabulate
import json
from collections import OrderedDict
import urlparse

_host_url = None
_default_host_url = "https://www.whetlab.com/"
_api_suffix = "/api/alpha/" # note the slash at the end

def _force_callback(ctx, param, value):
    if not value:
        ctx.abort()

def _is_finite(val):
    import math
    if val:
        val = float(val)
        return math.isnan(val) is False and math.isinf(val) is False
    else:
        return False

def make_url(path):
    global _api_suffix
    global _host_url
    config = whetlab.load_config()
    if "api_url" not in config.keys():
        _host_url = _default_host_url
    else:
        _host_url = config['api_url']
    return urlparse.urljoin(urlparse.urljoin(_host_url, _api_suffix), path)

def _check_request(r):
    if str(r.status_code)[0] != '2':
        print "HTTP %d" % r.status_code
        print r.text
        sys.exit()

def _write_config(access_token):
    out_path = os.path.expanduser('~/.whetlab')
    config = ConfigParser.RawConfigParser()
    config.add_section("whetlab")
    config.set("whetlab", "access_token", access_token)
    config.set("whetlab", "host", _host_url)
    with open(out_path, "w") as f:
        config.write(f)

def _get_login():
    username = click.prompt("Username")
    password = click.prompt("Password (input is hidden as you type)", hide_input=True)
    return username, password

def _get_access_token(force_server=False):
    config = whetlab.load_config()
    if "access_token" not in config.keys() or force_server:
        access_token = _get_access_token_from_server()
        return access_token
    else:
        return config['access_token']

def _get_auth():
    username,password,access_token = None,None,None
    config = whetlab.load_config()
    if "access_token" not in config.keys() or config["access_token"] == "":
        click.echo("Please log in to download your access token:")
        username, password = _get_login()
        access_token = None
    else:
        access_token = config['access_token']
    auth, headers = _format_auth(username, password, access_token)
    return auth, headers

def _format_auth(username=None, password=None, access_token=None):
    if access_token:
        auth = None
        headers = headers = {'Authorization': "Bearer " + access_token}
    elif None not in (username, password):
        auth = (username, password)
        headers = {}
    else:
        raise ValueError("Must provide either an access token or both username and password")
    return auth, headers


def _get_access_token_from_server():
    auth, headers = _get_auth()
    r = requests.get(make_url("access-token/"), auth=auth, headers=headers)
    _check_request(r)

    out = r.json()
    if out.has_key("access_token"):
        return r.json()['access_token']
    else:
        return ""

def _make_new_access_token():
    auth, headers = _get_auth()
    URL = make_url("access-token/")
    client = requests.session()
    client.get(URL,auth=auth,headers=headers)
    csrftoken = client.cookies['csrftoken']
    headers['X-CSRFToken'] = csrftoken
    r = client.post(URL, auth=auth, headers=headers)
    _check_request(r)

    out = r.json()
    print r.text
    if out.has_key("access_token"):
        access_token = r.json()['access_token']
    else:
        access_token = ""
    _write_config(access_token)
    return access_token

@click.group()
def main():
    """A command_line interface for interacting with Whetlab"""
    pass

@main.command(name="test")
def test():
    """Update the whetlab CLI tool.
    """
    click.echo(make_url("results/"))

# TODO: TEST
@main.command(name="update")
def update():
    """Update the whetlab CLI tool.
    """
    click.echo("Doing update...")
    if os.system("pip install whetlab --upgrade") == 0:
        click.echo("Update succeeded")
    else:
        click.echo("Update failed. For help email info@whetlab.com")

@main.command(name="setup")
def setup():
    """Log in and set up this machine to work with Whetlab
    """
    config = whetlab.load_config()
    if len(config.keys()) > 0: # if config setup
        yes = click.confirm("You've already set up Whetlab. Rerun setup?")
        if not yes: return
    
    global _host_url
    _host_url = None
    access_token = _get_access_token(force_server=True)
    click.echo("Setting up Whetlab config file...")
    _write_config(access_token)
    click.echo("All setup! Run whetlab get-token to see your access token.")

@main.command(name="get-token")
def get_token():
    """Get your API token (which you might use in your own code)
    """
    access_token = _get_access_token()
    click.echo("\nAccess Token: \n%s" % access_token)

@main.command(name="request-new-token")
def request_new_token():
    """Request a new API token
    """
    access_token = _make_new_access_token()
    click.echo("\nNew access token:\n%s\n" % access_token)
    click.echo("Your config file has also been updated.")

# Formatting functions
format_experiment = lambda exp: OrderedDict([("ID",exp['id']), ("Name",exp['name'])])
format_setting = lambda setting, setting_keys: OrderedDict([(key,setting[key]) for key in setting_keys])
format_result = lambda result, setting_names: OrderedDict([("ID",result['id'])]+
                    [(name,[v['value'] for v in result['variables'] if v['name']==name][0]) 
                     for name in setting_names])
format_experiments = lambda experiments_json: [format_experiment(exp) for exp in experiments_json]
format_results = lambda results_json,setting_names: [format_result(result,setting_names) for result in results_json]
def format_settings(settings_json):
    settings = sorted(settings_json,
        key=lambda s: (s['isOutput']==False,s['name']))
    settings = [format_setting(s,sorted(settings[0].keys())) for s in settings]
    return settings

def do_sort(results_json, results, sortby='id', reverse=False):
    if sortby in results_json[0].keys():
        index = sorted(range(len(results_json)), key=lambda k: results_json[k][sortby], reverse=reverse)
    elif sortby in results[0].keys():
        index = sorted(range(len(results)), key=lambda k: results[k][sortby], reverse=reverse)
    else:
        click.echo("\nCould not find key %s" % sortby)
        click.echo("Available keys are:")
        click.echo(results[0].keys()+results_json[0].keys())
        click.echo("\n")
        return results_json, results
    results_json = [results_json[i] for i in index]
    results = [results[i] for i in index]
    return results_json, results

# def _format_experiments()


def _format_output(json_data, output_format="table"):
    if output_format == "json":
        return json.dumps(json_data, indent=4)
    elif output_format == "csv":
        csv_string = ",".join(json_data[0].keys()) # the header
        csv_string += "\n" # newline
        for data in json_data: # each result
            csv_string += ",".join([str(i) for i in data.values()])+"\n"
        return csv_string
    elif output_format == "table":
        return tabulate(json_data, headers='keys', numalign='center', stralign='center')
    
@main.command(name="get-results")
@click.argument("experiment", type=int)
@click.option("--json", 'output_format', flag_value='json', help='Format output as JSON')
@click.option("--csv", 'output_format', flag_value='csv', help='Format output as CSV')
@click.option("--table", 'output_format', flag_value='table', help="Format output in a table", default=True)
@click.option("--sortby", '-s', help="Sort the rows by a key (descending)", default='ID')
@click.option("--reverse/--no-reverse", "-r", help="Reverse the sort order", default=False)
def get_results(experiment, output_format, sortby, reverse):
    """List all results from a particular experiment
    """
    auth, headers = _get_auth()
    r = requests.get(make_url("experiments/%d/?page_size=99999&showresults=1"%experiment), auth=auth, headers=headers)
    _check_request(r)

    experiment_data = r.json()
    if not experiment_data.has_key("results"):
        click.echo("No results for experiment ID %d" % experiment)
        return 

    settings_json = experiment_data['settings']
    results_json = experiment_data['results']
    settings = format_settings(settings_json)
    results = format_results(results_json, [s['name'] for s in settings])

    if len(results) == 0:
        click.echo("No results yet!")
        return

    results_json, results = do_sort(results_json, results, sortby, reverse)
    click.echo(_format_output(results if output_format!="json" else results_json, 
                                output_format))

@main.command(name="best-result")
@click.argument("experiment", type=int)
@click.option("--json", 'output_format', flag_value='json', help='Format output as JSON')
@click.option("--csv", 'output_format', flag_value='csv', help='Format output as CSV')
@click.option("--table", 'output_format', flag_value='table', help="Format output in a table", default=True)
def best_result(experiment, output_format):
    """Display the current best result
    """
    auth, headers = _get_auth()
    r = requests.get(make_url("experiments/%d/?showresults=1"%experiment), auth=auth, headers=headers)
    _check_request(r)

    experiment_data = r.json()
    if not experiment_data.has_key("results"):
        click.echo("No results for experiment ID %d" % experiment)
        return 

    settings_json = experiment_data['settings']
    results_json = experiment_data['results']
    settings = format_settings(settings_json)
    outputName = settings[0]['name'] # the "output" setting is always the first
    results = format_results(results_json, [s['name'] for s in settings])
    results = [res for res in sorted(results, key=lambda t:t[outputName],reverse=True) 
               if _is_finite(res[outputName])][:1]

    if len(results):
        results_json = [res for res in results_json if res['id'] == results[0]['ID']]
        click.echo(_format_output(results if output_format!="json" else results_json, output_format))
    else:
        click.echo("\nNo best results yet")
    return

@main.command(name="get-experiments")
@click.option("--json", 'output_format', flag_value='json', help='Format output as JSON')
@click.option("--csv", 'output_format', flag_value='csv', help='Format output as CSV')
@click.option("--table", 'output_format', flag_value='table', help="Format output in a table", default=True)
@click.option("--sortby", '-s', help="Sort the rows by a key (descending)", default='ID')
@click.option("--reverse/--no-reverse", "-r", help="Reverse the sort order", default=False)
def get_experiments(output_format,sortby,reverse):
    """List all experiments.

    Defaults to dumping the experiment IDs, but you can pass
    in the --full (or -f) flag to dump everything.
    """
    auth, headers = _get_auth()
    r = requests.get(make_url("experiments/?page_size=99999"), auth=auth, headers=headers)
    _check_request(r)

    experiments_json = r.json()['results']
    experiments = format_experiments(experiments_json)
    experiments_json, experiments = do_sort(experiments_json, experiments, sortby, reverse)
    click.echo(_format_output(experiments if output_format!="json" else experiments_json, 
        output_format))
    return

@main.command(name="get-result")
@click.argument("result", type=int)
@click.option("--json", 'output_format', flag_value='json', help='Format output as JSON')
@click.option("--csv", 'output_format', flag_value='csv', help='Format output as CSV')
@click.option("--table", 'output_format', flag_value='table', help="Format output in a table", default=True)
def get_result(result, output_format):
    """Get all data for a single result by ID
    """
    auth, headers = _get_auth()
    r = requests.get(make_url("results/%d/"%result), auth=auth, headers=headers)
    _check_request(r)
    result_json = r.json()
    setting_names = sorted([v['name'] for v in result_json['variables']])
    result = format_result(result_json, setting_names)
    click.echo(_format_output([result] if output_format!="json" else result_json, 
        output_format))
    return

@main.command(name="get-experiment")
@click.argument("experiment", type=int)
@click.option("--json", 'output_format', flag_value='json', help='Format output as JSON')
@click.option("--csv", 'output_format', flag_value='csv', help='Format output as CSV')
@click.option("--table", 'output_format', flag_value='table', help="Format output in a table", default=True)
def get_experiment(experiment, output_format):
    """List all data from an experiment
    """
    auth, headers = _get_auth()
    r = requests.get(make_url("experiments/%d/?showresults=1"%experiment), auth=auth, headers=headers)
    _check_request(r)

    experiment_data = r.json()
    if not experiment_data.has_key("results"):
        click.echo("No results for experiment ID %d" % experiment)
        return 

    settings_json = experiment_data['settings']
    results_json = experiment_data['results']
    settings = format_settings(settings_json)
    results = format_results(results_json, [s['name'] for s in settings])

    if output_format != "json":
        click.echo("\nSettings:\n" if output_format=="table" else "\n")
        click.echo(_format_output(settings if output_format!="json" else settings_json, 
            output_format))
        click.echo("\nResults:\n" if output_format=="table" else "\n")
        click.echo(_format_output(results if output_format!="json" else results_json, 
                output_format))
    else:
        click.echo(_format_output(experiment_data, output_format))

    return


@main.command(name="get-settings")
@click.argument("experiment", type=int)
@click.option("--json", 'output_format', flag_value='json', help='Format output as JSON')
@click.option("--csv", 'output_format', flag_value='csv', help='Format output as CSV')
@click.option("--table", 'output_format', flag_value='table', help="Format output in a table", default=True)
@click.option("--sortby", '-s', help="Sort the rows by a key (descending)", default='id')
@click.option("--reverse/--no-reverse", "-r", help="Reverse the sort order", default=False)
def get_settings(experiment, output_format, sortby, reverse):
    """Get all settings from an experiment
    """
    auth, headers = _get_auth()
    r = requests.get(make_url("settings/?page_size=99999&experiment=%d"%experiment), auth=auth, headers=headers)
    _check_request(r)

    settings_json = r.json()
    if not settings_json.has_key("results"):
        click.echo("No results for experiment ID %d" % experiment)
        return 
    settings_json = settings_json['results']
    settings = format_settings(settings_json)
    settings_json, settings = do_sort(settings_json, settings, sortby, reverse)
    click.echo(_format_output(settings if output_format!="json" else settings_json, 
                output_format))
    return

@main.command(name="get-setting")
@click.argument("setting", type=int)
@click.option("--json", 'output_format', flag_value='json', help='Format output as JSON')
@click.option("--csv", 'output_format', flag_value='csv', help='Format output as CSV')
@click.option("--table", 'output_format', flag_value='table', help="Format output in a table", default=True)

def get_setting(setting, output_format):
    """Get all data for a single setting by ID
    """
    auth, headers = _get_auth()
    r = requests.get(make_url("settings/%d/"%setting), auth=auth, headers=headers)
    _check_request(r)

    setting_json = r.json()
    setting = format_settings([setting_json])
    click.echo(_format_output(setting if output_format!="json" else setting_json, 
            output_format))

    return

@main.command(name="delete-experiment")
@click.argument("experiments", type=int, nargs=-1)
@click.option('--force', '-f', is_flag=True, callback=_force_callback,
              expose_value=False, prompt='Delete experiment(s)?')
def delete_experiment(experiments):
    """Delete an experiment by ID
    """
    auth, headers = _get_auth()
    for experiment in experiments:
        r = requests.delete(make_url("experiments/%d/"%experiment), auth=auth, headers=headers)
        _check_request(r)
    return 

@main.command(name="delete-result")
@click.argument("results", type=int, nargs=-1)
@click.option('--force', '-f', is_flag=True, callback=_force_callback,
              expose_value=False, prompt='Delete result(s)?')
def delete_result(results):
    """Delete an result by ID
    """
    auth, headers = _get_auth()
    for result in results:
        r = requests.delete(make_url("results/%d/"%result), auth=auth, headers=headers)
        _check_request(r)
    return 

@main.command(name="update-experiment")
@click.argument("experiment", type=int)
@click.argument("data", type=str, required=False, default="")
def update_experiment(experiment, data):
    """Update the results, settings, name or description of an experiment
    """

    if data == "":
        if select.select([sys.stdin,],[],[],0.0)[0]:
            for line in sys.stdin:
                if not line: 
                    break
                data += line
        else:
            click.echo("No data provided.")
            return

    json_data = json.loads(data)
    auth, headers = _get_auth()
    headers['content-type'] = 'application/json'
    r = requests.patch(make_url("experiments/%d/"%experiment), data=json.dumps(json_data), auth=auth, headers=headers)
    _check_request(r)


@main.command(name="update-result")
@click.argument("result", type=int)
@click.argument("data", type=str, required=False, default="")
def update_result(result, data):
    """Update the results, settings, name or description of an result
    """

    if data == "":
        if select.select([sys.stdin,],[],[],0.0)[0]:
            for line in sys.stdin:
                if not line: 
                    break
                data += line
        else:
            click.echo("No data provided.")
            return

    json_data = json.loads(data)
    auth, headers = _get_auth()
    headers['content-type'] = 'application/json'
    r = requests.patch(make_url("results/%d/"%result), data=json.dumps(json_data), auth=auth, headers=headers)
    print r
    _check_request(r)

@main.command(name="update-setting")
@click.argument("setting", type=int)
@click.argument("data", type=str, required=False, default="")
def update_setting(setting, data):
    """Update the settings, settings, name or description of an setting
    """

    if data == "":
        if select.select([sys.stdin,],[],[],0.0)[0]:
            for line in sys.stdin:
                if not line: 
                    break
                data += line
        else:
            click.echo("No data provided.")
            return

    json_data = json.loads(data)
    auth, headers = _get_auth()
    headers['content-type'] = 'application/json'
    r = requests.patch(make_url("settings/%d/"%setting), data=json.dumps(json_data), auth=auth, headers=headers)
    _check_request(r)

@main.command(name="new-experiment")
@click.argument("data", type=str, required=False, default="")
def new_experiment(data):
    """Create the results, settings, name or description of an experiment
    """

    if data == "":
        if select.select([sys.stdin,],[],[],0.0)[0]:
            for line in sys.stdin:
                if not line: 
                    break
                data += line
        else:
            click.echo("No data provided.")
            return
    json_data = json.loads(data)

    auth, headers = _get_auth()
    headers['content-type'] = 'application/json'
    r = requests.post(make_url("experiments/"), data=json.dumps(json_data), auth=auth, headers=headers)
    _check_request(r)


@main.command(name="new-result")
@click.argument("data", type=str, required=False, default="")
def new_result(data):
    """Create the results, settings, name or description of an result
    """

    if data == "":
        if select.select([sys.stdin,],[],[],0.0)[0]:
            for line in sys.stdin:
                if not line: 
                    break
                data += line
        else:
            click.echo("No data provided.")
            return
    json_data = json.loads(data)

    auth, headers = _get_auth()
    headers['content-type'] = 'application/json'
    r = requests.post(make_url("results/"), data=json.dumps(json_data), auth=auth, headers=headers)
    _check_request(r)

@main.command(name="suggest")
@click.argument("experiment", type=int)
@click.option("--sync", 'sync', flag_value=True, help='Format output as JSON')
@click.option("--async", 'sync', flag_value=False, help='Format output as CSV', default=False)
@click.option("--json", 'output_format', flag_value='json', help='Format output as JSON')
@click.option("--csv", 'output_format', flag_value='csv', help='Format output as CSV')
@click.option("--table", 'output_format', flag_value='table', help="Format output in a table", default=True)
def suggest(experiment, sync, output_format):
    """Ask for a new suggestion. Returns with the result ID, which you can poll
    periodically until the suggestion is ready."""
    from time import sleep
    auth, headers = _get_auth()
    r = requests.post(make_url("experiments/%d/suggest/"%experiment), auth=auth, headers=headers)
    _check_request(r)
    result_id = r.json()['id']
    if sync:
        while 1:
            r = requests.get(make_url("results/%d/"%result_id), auth=auth, headers=headers)
            _check_request(r)
            result_json = r.json()
            if result_json['suggestionDate'] is None: 
                sleep(1)
                continue
            else:
                setting_names = sorted([v['name'] for v in result_json['variables']])
                result = format_result(result_json, setting_names)
                click.echo(_format_output([result] if output_format!="json" else result_json, 
                    output_format))
                break

    else:
        click.echo({"id":result_id})


if __name__ == "__main__":
    main()