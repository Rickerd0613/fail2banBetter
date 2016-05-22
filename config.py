ssh = dict(
    log = '/var/log/auth.log',
    regex = 'regexSSH',
    lastLogSize = 0,
)

apache = dict(
    log = '/var/log/apache2/access.log',
    regex = 'regexAPACHE',
    lastLogSize = 0,
)

vnc = dict(
    log = '/home/pi/.vnc/raspberrypi:1.log',
    regex = 'regexVNC',
    lastLogSize = 0,
)