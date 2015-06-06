# ClientException is used when the api returns an error
class ClientError(Exception):

	def __init__(self, message, code):
		super(ClientError, self).__init__()
		self.message = message
		self.code = code

		def __str__(self):
			return 'Error code: ' + str(self.code) + ' Server message: ' + str(self.message)
