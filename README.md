# Sure Petcare Control

A commandline tool to lock, unlock and change the curfew of the Sure Petcare Petflap.

Commands:
```bash
spc lock
spc unlock
spc curfew 22:00 06:00
```

**The time must always be given in the format HH:MM as shown above**

The secrets have to be set as environment variables:
SPC_EMAIL=login@domain
SPC_PASSWORD=your_password
SPC_DEVICE_ID=device_id_from_uri

The device id can be sniffed with a proxy from the lock command.
