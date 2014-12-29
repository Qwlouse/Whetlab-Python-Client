# NOTE:
# Bug in click: if type="integer", click doesn't provide interpretable error

import os, sys, select, re
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
    config.set("whetlab", "api_url", _host_url)
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

def _validate_type(setting_type):
    if setting_type not in ['float', 'integer', 'enum']:
        click.echo("Invalid setting type %s. Must be float, integer or enum" % setting_type)
        sys.exit()
    return setting_type

def _check_name_is_good(name):
    validpat = re.compile('^[a-zA-Z_][a-zA-Z0-9_-]*\Z')
    if validpat.match(name) is None:
        return False
    else:
        return True

def _validate_name(name):
    return name

    # TODO:
    # Stricter name validation on the server
    # if not _check_name_is_good(name):
    #     click.echo("Name %s is invalid." % name)
    #     sys.exit()
    # return name

def _validate_options(options):
    for option in options:
        if not _check_name_is_good(option):
            error_msg = "Invalid option name %s. " % option
            error_msg += "Must begin with a letter and not contain special characters besides underscore and dash"
            click.echo(error_msg)
            sys.exit()
    return options

def _validate_size(size):
    if not ((size > 0) & (size < 30)):
        click.echo("Invalid size %d. Must be greater than 0 and less than 30" % size)
        sys.exit()
    return size

def _validate_bounds(minimum, maximum, size):
    if size == 1:
        if maximum <= minimum:
            click.echo("\nMinimum %s is greater than maximum %s" % (str(minimum), str(maximum)))
            sys.exit()
    else:
        for dim,(mx,mn) in enumerate(zip(maximum, minimum)):
            if mx <= mn: 
                click.echo("\nMinimum %s is greater than maximum %s for dimension %d" % (str(mn), str(mx), dim+1))
                sys.exit()
    return minimum, maximum

def _count(val):
    """Count the number of entries in val, robust to scalars and iterables"""
    if isinstance(val, (tuple, list, set)):
        return len(val)
    if isinstance(val, (str, unicode)):
        return 1
    if isinstance(val, (float, int, long)):
        return 1

def prompt(text, nargs=1, sep=",", type=str, **kwargs):
    if nargs==1:
        out = click.prompt(text, type=type, **kwargs)
        if out is None:
            sys.exit()
        else:
            return out
    elif (nargs==-1) or (nargs > 1):
        out = click.prompt(text, type=str, **kwargs)
        if out is None:
            sys.exit()
        if sep != " ":
            out = out.replace(" ", "")
        out = map(type, out.split(sep))
        if (nargs != -1) & (len(out) != nargs):
            click.echo("Invalid number of inputs. Expected %d, found %d" % (nargs, len(out)))
            sys.exit()
        else:
            return out
    else:
        raise ValueError("nargs must be -1 (infinite) or > 1")

def prompt_setting(setting=None):

    out_setting = OrderedDict(name=None,
                              isOutput=False,
                              type=None,
                              size=None,
                              min=None,
                              max=None,
                              options=None)

    # If no setting is provided, we'll ask for a fresh setting, with no defaults
    if setting is None:
        out_setting['name'] = ""
        out_setting['isOutput'] = False
        out_setting['type'] = "float"
        out_setting['size'] = 1
        out_setting['min'] = None
        out_setting['max'] = None
        out_setting['options'] = None
        setting = out_setting

    # However, if a setting is provided, we'll prompt for a modification of the passed setting
    else:
        out_setting['name'] = setting['name']
        out_setting['isOutput'] = setting['isOutput']
        out_setting['type'] = setting['type']
        out_setting['size'] = setting['size']
        out_setting['min'] = setting['min']
        out_setting['max'] = setting['max']
        out_setting['options'] = setting['options']

    if out_setting['name'] == "":
        name_prefix = "(hit Enter to finish)"
    else:
        name_prefix = ""
    out_setting['name'] = prompt("Name %s" % name_prefix, default=out_setting['name'], type=str)
    # NOTE: HACK: 
    # If we don't provide a name, we'll consider this the end of the road
    # This is a nasty side-effect, but it allows us to do early-stopping
    # while creating lists of settings for a new experiment
    if out_setting['name'] == "":
        return out_setting
    out_setting['name'] = _validate_name(out_setting['name'])

    # No other options are needed if the setting is an output
    if out_setting['isOutput'] == True:
        return out_setting

    # Type
    out_setting['type'] = prompt("Type (float,integer or enum)", default=out_setting['type'], type=str)
    out_setting['type'] = _validate_type(out_setting['type'])

    # Size
    out_setting['size'] = prompt("Size (dimension of parameter)", default=out_setting['size'], type=int)
    out_setting['size'] = _validate_size(out_setting['size'])
    
    # If enum
    suffix_text = "" if out_setting['size'] == 1 else "(comma separated, must match size of %d)" % out_setting['size']

    if out_setting['type'] == "enum":
        # Get the default options (might not be able to get one if we've changed size or type earlier)
        if out_setting['options'] != None:
            out_setting['options'] = ",".join(out_setting['options'])
        out_setting['options'] = prompt("Options %s" % suffix_text, nargs=-1, default=out_setting['options'], type=str)
        out_setting['options'] = _validate_options(out_setting['options'])

    elif out_setting['type'] in ("float", "integer"):

        # Get the default minimum (might not be able to get one if we've changed size or type earlier)
        if (out_setting['size'] == setting['size']) and (_count(setting['min']) == out_setting['size']):
            out_setting['min'] = setting['min']
        else:
            out_setting['min'] = None

        # Get the default maximum (might not be able to get one if we've changed size or type earlier)
        if (out_setting['size'] == setting['size']) and (_count(setting['max']) == out_setting['size']):
            out_setting['max'] = setting['max']
        else:
            out_setting['max'] = None

        expected_type = int if out_setting['type']=="integer" else float
        out_setting['min'] = prompt("Min %s" % suffix_text, nargs=out_setting['size'], default=out_setting['min'], type=expected_type)
        out_setting['max'] = prompt("Max %s" % suffix_text, nargs=out_setting['size'], default=out_setting['max'], type=expected_type)
        out_setting['min'], out_setting['max'] = _validate_bounds(out_setting['min'], out_setting['max'], out_setting['size'])

    return out_setting

def prompt_result(result, settings):
    if result == None:
        default_variables = [OrderedDict(name=s['name'],
                                         setting=s['id'],
                                         value=None) for s in settings]
        out_result = OrderedDict(userProposed=True, 
                            experiment=settings[0]['experiment'],
                            variables=default_variables)
    else:
        out_result = result
        variables = []
        for setting_name in [s['name'] for s in settings]:
            for v in out_result['variables']:
                if v['name'] == setting_name:
                    variables.append(v)
        out_result['variables'] = variables

    variables = []
    for i,(variable,setting) in enumerate(zip(out_result['variables'], settings)):
        _default_value = None if not variable.has_key("value") else variable['value']

        expected_type = {"float":float,
                         "integer":int,
                         "enum":str}[setting['type']]
        variable['value'] = prompt(variable['name'], nargs=setting['size'], default=_default_value, type=expected_type)
        variables.append(variable)
    out_result['variables'] = variables

    return out_result

def prompt_experiment(experiment=None):
    if experiment == None:
        out_experiment = OrderedDict(name=None, description='')
    else:
        out_experiment = OrderedDict(name=experiment['name'], description=experiment['description'])

    out_experiment['name'] = prompt("Name", default=out_experiment['name'], type=str)
    out_experiment['description'] = prompt("Description", default=out_experiment['description'], type=str)

    return out_experiment

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
    
    config_filepath = whetlab.find_config_file()
    if config_filepath:
        os.remove(config_filepath)
    
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
    if len(results):
        click.echo(_format_output(results if output_format!="json" else results_json, 
                                    output_format))
    else:
        click.echo("No results yet")

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
        if len(settings):
            click.echo(_format_output(settings if output_format!="json" else settings_json, 
                output_format))
        else:
            click.echo("No settings yet")

        click.echo("\nResults:\n" if output_format=="table" else "\n")
        if len(results):
            click.echo(_format_output(results if output_format!="json" else results_json, 
                    output_format))
        else:
            click.echo("No results yet")
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
    if len(settings):
        click.echo(_format_output(settings if output_format!="json" else settings_json, 
                    output_format))
    else:
        click.echo("No settings yet")
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
@click.option("--interactive/--no-interactive", "-i", help="Update a result interactively", default=True)
def update_experiment(experiment, data, interactive):
    """Update the results, settings, name or description of an experiment
    """


    if data == "":
        if select.select([sys.stdin,],[],[],0.0)[0]:
            for line in sys.stdin:
                if not line: 
                    break
                data += line
        else:
            # If we do not want to allow interactive updating, then exit
            if not interactive:
                click.echo("No data provided.")
                return

    auth, headers = _get_auth()

    # If data wasn't passed in as a JSON string, or piped,
    # then we'll grab it interactively
    if data == "":
        r = requests.get(make_url("experiments/%d/"%experiment), auth=auth, headers=headers)
        _check_request(r)
        experiment_data = r.json()
        experiment_data = prompt_experiment(experiment_data)
        data = json.dumps(experiment_data)        

    headers['content-type'] = 'application/json'
    r = requests.patch(make_url("experiments/%d/"%experiment), data=data, auth=auth, headers=headers)
    _check_request(r)

@main.command(name="update-result")
@click.argument("result", type=int)
@click.argument("data", type=str, required=False, default="")
@click.option("--interactive/--no-interactive", "-i", help="Update a result interactively", default=True)
def update_result(result, data, interactive):
    """Update the results, settings, name or description of an result
    """

    if data == "":
        if select.select([sys.stdin,],[],[],0.0)[0]:
            for line in sys.stdin:
                if not line: 
                    break
                data += line
        else:
            # If we do not want to allow interactive updating, then exit
            if not interactive:
                click.echo("No data provided.")
                return

    auth, headers = _get_auth()

    # If data wasn't passed in as a JSON string, or piped,
    # then we'll grab it interactively
    if data == "":

        # First, get the result to update
        r = requests.get(make_url("results/%d/"%result), auth=auth, headers=headers)
        _check_request(r)
        result_data = r.json()

        # Get the settings (so that we might order the variables properly)
        experiment = result_data['experiment']
        r = requests.get(make_url("settings/?page_size=99999&experiment=%d"%experiment), auth=auth, headers=headers)
        _check_request(r)
        settings = format_settings(r.json()['results'])

        # Get the result data
        result_data = prompt_result(result_data, settings)

        # Turn it into JSON
        data = json.dumps(result_data)

    # Send it out over the wire
    headers['content-type'] = 'application/json'
    r = requests.patch(make_url("results/%d/"%result), data=data, auth=auth, headers=headers)
    _check_request(r)

@main.command(name="update-setting")
@click.argument("setting", type=int)
@click.argument("data", type=str, required=False, default="")
@click.option('--force', '-f', is_flag=True)
def update_setting(setting, data, force):
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

    if not force:
        if "min" in json_data or "max" in json_data or "options" in json_data:
            click.echo("\nSetting a new min, max or options on a setting ")
            click.echo("will cause results that fall out of bounds to be deleted.")
            click.echo("If you want, you can first clone a backup of the experiment with e.g.\n")
            click.echo("> whetlab clone-experiment EXPERIMENT-ID\n")
            if not click.confirm("Do you wish to continue?"):
                return

    auth, headers = _get_auth()
    headers['content-type'] = 'application/json'
    r = requests.patch(make_url("settings/%d/"%setting), data=json.dumps(json_data), auth=auth, headers=headers)
    _check_request(r)

@main.command(name="new-experiment")
@click.argument("data", type=str, required=False, default="")
@click.option("--interactive/--no-interactive", "-i", help="Update a result interactively", default=True)
def new_experiment(data, interactive):
    """Create the results, settings, name or description of an experiment
    """


    if data == "":
        if select.select([sys.stdin,],[],[],0.0)[0]:
            for line in sys.stdin:
                if not line: 
                    break
                data += line
        else:
            # If we do not want to allow interactive updating, then exit
            if not interactive:
                click.echo("No data provided.")
                return

    auth, headers = _get_auth()

    # If data wasn't passed in as a JSON string, or piped,
    # then we'll grab it interactively
    if data == "":
        # First get the experiment name and description
        experiment_data = prompt_experiment(None)

        # Then get the settings
        click.echo("Settings:")
        click.echo("Output Setting (only one output per experiment)")
        output_setting = prompt_setting({"name": "", 
                                        "isOutput":True,
                                        "min": None, 
                                        "max": None, 
                                        "options": None, 
                                        "size": 1,
                                        "type": "float"})
        settings = [output_setting]
        click.echo("\n")
        click.echo("Input Settings (up to 30):")
        for i in range(30):
            click.echo("==================================================")
            setting = prompt_setting(None)
            if setting['name'] == '':
                break
            settings.append(setting)
        experiment_data['settings'] = settings

        # Then dump it to JSON
        data = json.dumps(experiment_data)

    # Now, POST the data to the sky
    headers['content-type'] = 'application/json'
    r = requests.post(make_url("experiments/"), data=data, auth=auth, headers=headers)
    _check_request(r)

# @main.command(name="clone-experiment")
# @click.argument("experiment", type=int)
# @click.argument("data", type=str, required=False, default="")
# @click.option("--interactive/--no-interactive", "-i", help="Update a result interactively", default=True)
# def clone_experiment(experiment, data, interactive):
#     """Clone an experiment (settings and results)
#     """

#     # First, get the experiment we'd like to clone
#     auth, headers = _get_auth()
#     r = requests.get(make_url("experiments/%d/?showresults=1"%experiment), auth=auth, headers=headers)
#     _check_request(r)
#     experiment_data = r.json()
#     if not experiment_data.has_key("results"):
#         click.echo("No results for experiment ID %d" % experiment)
#         return 
#     settings_json = experiment_data['settings']
#     results_json = experiment_data['results']
#     old_settings = format_settings(settings_json)
#     results = format_results(results_json, [s['name'] for s in old_settings])

#     # If we've piped in new experiment data, then let's use that
#     if data == "":
#         if select.select([sys.stdin,],[],[],0.0)[0]:
#             for line in sys.stdin:
#                 if not line: 
#                     break
#                 data += line
#             experiment_data.update(json.loads(data))
#         else:
#             # If we do not want to allow interactive updating, then exit
#             if not interactive:
#                 click.echo("No data provided.")
#                 return


#     # If data wasn't passed in as a JSON string, or piped,
#     # then we'll grab it interactively
#     if interactive and data == "":
#         # First get the experiment name and description
#         experiment_data['name'] = "Copy of " + experiment_data['name']
#         experiment_data = prompt_experiment(experiment_data)

#         # Then get the settings
#         click.echo("Settings:")
#         click.echo("Output Setting (only one output per experiment)")
#         new_settings = []
#         for setting in old_settings:
#             out_setting = prompt_setting(setting)
#             new_settings.append(out_setting)
#         experiment_data['settings'] = new_settings

#     # Now, POST the data to the sky
#     headers['content-type'] = 'application/json'
#     r = requests.post(make_url("experiments/"), data=json.dumps(experiment_data), auth=auth, headers=headers)
#     _check_request(r)
#     experiment_id = r.json()['id']

#     # Match the new settings to the result variables
#     r = requests.get(make_url("settings/?page_size=99999&experiment=%d"%experiment_id), auth=auth, headers=headers)
#     _check_request(r)
#     new_settings = format_settings(r.json()['results']) # this is to get the IDs only, really.


#     # Make a map between old and new settings
#     # For each result
#     click.echo("\nCloning experiment (this could take a few minutes for large experiments...)\n")
#     for iresult in range(len(results_json)):
#         # For each old setting
#         results_json[iresult] = dict(experiment=experiment_id,
#                                      userProposed=results_json[iresult]['userProposed'],
#                                      variables=results_json[iresult]['variables'])
#         for old_setting,new_setting in zip(old_settings,new_settings):
#             # Find the variable for the old setting
#             for ivar in range(len(results_json[iresult]['variables'])):
#                 result = results_json[iresult]
#                 if result['variables'][ivar]['name'] != old_setting['name']:
#                     continue
#                 val = result['variables'][ivar]['value']
#                 # Update its setting for the new setting, and include its value
#                 results_json[iresult]['variables'][ivar] = dict(setting=new_setting['id'], value=val, name=new_setting['name'])

#     # Remove results whose values are out of bounds
#     valid_results_json = []
#     for iresult in range(len(results_json)):
#         # For each old setting
#         keep = True
#         for new_setting in new_settings:
#             # Find the variable for the old setting
#             for ivar in range(len(results_json[iresult]['variables'])):
#                 result = results_json[iresult]
#                 if result['variables'][ivar]['name'] != new_setting['name']:
#                     continue
#                 val = result['variables'][ivar]['value']
#                 # Update its setting for the new setting, and include its value
#                 if new_setting['type'] != 'enum':
#                     if not ((val >= new_setting['min']) & (val <= new_setting['max'])):
#                         keep = False
#                 elif new_setting['type'] == 'enum':
#                     if val not in new_setting['options']:
#                         keep = False
#         if keep:
#             valid_results_json.append(results_json[iresult])


#     # TODO:
#     # Concurrency with multiprocessing.
#     for result in valid_results_json:
#         r = requests.post(make_url("results/"), data=json.dumps(result), auth=auth, headers=headers)
#         _check_request(r)

@main.command(name="new-result")
@click.argument("experiment", type=int)
@click.argument("data", type=str, required=False, default="")
@click.option("--interactive/--no-interactive", "-i", help="Update a result interactively", default=True)
def new_result(experiment, data, interactive):
    """Create the results, settings, name or description of an result
    """


    if data == "":
        if select.select([sys.stdin,],[],[],0.0)[0]:
            for line in sys.stdin:
                if not line: 
                    break
                data += line
        else:
            # If we do not want to allow interactive updating, then exit
            if not interactive:
                click.echo("No data provided.")
                return

    auth, headers = _get_auth()

    # If data wasn't passed in as a JSON string, or piped,
    # then we'll grab it interactively
    if data == "":
        r = requests.get(make_url("settings/?page_size=99999&experiment=%d"%experiment), auth=auth, headers=headers)
        _check_request(r)
        settings = format_settings(r.json()['results'])

        # Get the result data
        result_data = prompt_result(None, settings)

        # Turn it into JSON
        data = json.dumps(result_data)


    headers['content-type'] = 'application/json'
    r = requests.post(make_url("results/"), data=data, auth=auth, headers=headers)
    _check_request(r)

@main.command(name="clone-experiment")
@click.argument("experiment", type=int)
@click.argument("data", type=str, required=False, default="")
@click.option("--interactive/--no-interactive", "-i", help="Update a result interactively", default=False)
def clone_experiment(experiment, data, interactive):
    """Clone an experiment"""

    if data == "":
        if select.select([sys.stdin,],[],[],0.0)[0]:
            for line in sys.stdin:
                if not line: 
                    break
                data += line
        else:
            # If we do not want to allow interactive updating, then exit
            data = '{}'

    auth, headers = _get_auth()
    headers['content-type'] = 'application/json'
    r = requests.post(make_url("experiments/%d/clone/"%experiment), data=data, auth=auth, headers=headers)
    _check_request(r)


@main.command(name="suggest")
@click.argument("experiment", type=int)
@click.option("--sync", 'sync', flag_value=True, help='Return only when suggestion has been completed')
@click.option("--async", 'sync', flag_value=False, help='Return immediately, even if suggestion has not been completed', default=False)
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