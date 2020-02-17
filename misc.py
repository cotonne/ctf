from hashlib import md5

h = md5()
h.update('test')
h.update('!')
print(h.hexdigest())
