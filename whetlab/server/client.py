from .http_client import HttpClient

# Assign all the api classes
from .api.result import Result
from .api.variables import Variables
from .api.experiment import Experiment
from .api.settings import Settings
from .api.users import Users
from .api.results import Results
from .api.suggest import Suggest
from .api.experiments import Experiments
from .api.setting import Setting

class Client():

	def __init__(self, auth = {}, options = {}):
		self.http_client = HttpClient(auth, options)

	# Manipulate a result set indexed by its id
	#
	# id - Identifier of a result
	def result(self, id):
		return Result(id, self.http_client)

	# Returns the variables set for a user
	#
	def variables(self):
		return Variables(self.http_client)

	# Manipulate the experiment indexed by id.
	#
	# id - Identifier of corresponding experiment
	def experiment(self, id):
		return Experiment(id, self.http_client)

	# Returns the settings config for an experiment
	#
	def settings(self):
		return Settings(self.http_client)

	# Return user list
	#
	def users(self):
		return Users(self.http_client)

	# Manipulate the results set for an experiment given filters
	#
	def results(self):
		return Results(self.http_client)
		return Experiments(self.http_client)

	# Ask the server to propose a new set of parameters to run the next experiment
	#
	# exptid - Identifier of corresponding experiment
	def suggest(self, exptid):
		return Suggest(exptid, self.http_client)

	# Returns the experiments set for a user
	#
	def experiments(self):
		return Experiments(self.http_client)

	# Manipulate an experimental settings object
	#
	def setting(self):
		return Setting(self.http_client)

