# Client should be able to send and retrieve files.
# It should ask the server where to send it and then it should send those files to the host
# When retrieving files clients should ask the server for that specific file.
# Files will be encrypted through the fastes encryption algorithm (XChaCha20?) which proves to be
# enough for years (maybe add an option to extra security, changing the algorithm for something slower?)
# The key to descrypt those files will be sent to the server. Any time a new client connects with its
# credentials. It will be sent the key to the files.