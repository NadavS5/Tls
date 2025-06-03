# Tls 1.2 Client in python
Simple python implementation of tls 1.2 client
## How To Use
```python

from client import tls_connection

#create tls connection object
connection = tls_connection("www.google.com", 443)
connection.connect()
connection.send(b"any byte data you want")
full_message = connection.recv()
```
alternatively you can just run the main file to run simple http request.

 note that the recv() doesnt has a size param because it recieves a whole tls packet <br/>
 note that the message can be split across multiple packets

## Requirements:
```
pip install -r requirements.txt
```
> [!NOTE]
> Because the certificate chaining is not implemented yet you will need to download the wr2 certificate and it will support part of Google's websites
> [wr2 cert](https://i.pki.goog/wr2.crt) <br/>
> If you want to remove the cert verification remove lines 187 - 188 in client.py
## Current Implementation:

- This client uses cipher: ECDHE_RSA_AES256_GCM_SHA384 
> This cipher is used because most server support it
- and signature algorithm: RSA_PSS_RSAE_SHA256

## Why Not Tls 1.3?
because tls 1.3 is a little bit mor longer to implement and most servers still support tls 1.2 with the chosen cipher

---

## Development Status:

currently working on full certificate chaining verification 



## Note

This is a personal/educational project. You're more than welcome to browse the code, use it as a reference, or contribute!

Feel free to open pull requests.
