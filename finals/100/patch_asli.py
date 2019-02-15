def binary_patching(pattern, patch):
	inputstream = open('100', 'r').read()
	assert inputstream.count(pattern) <= 1
	result = inputstream.replace(pattern, patch)
	outputfile = open('100', 'w')
	outputfile.write(result)
	outputfile.close()


pattern = "9\302u\026\213\005\263\226 "
patch = "8\302u\026\213\005\263\226 "
binary_patching(pattern, patch)
