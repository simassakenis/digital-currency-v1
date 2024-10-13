# digital-currency-v1

Implementation of digital currency.

There is a dependency on libsodium (for hashing and digital signatures). Follow the installation instructions from https://doc.libsodium.org/installation.

Compile server program:
```
gcc -o server server.c -lsodium
```

Launch server program:
```
./server
```

Test server program:
```
curl http://localhost:8080
```

Send new transaction:
```
curl "http://localhost:8080/?sender_public_key=0XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&recipient_public_key=0XBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB&value_transferred=0X1234567890ABCDEF&nonce=0X234567890ABCDEF1234567890ABCDEF1&hash=0XDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF&digital_signature=0X1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
```

Test via browser:
* http://localhost:8080
* http://localhost:8080/?sender_public_key=0XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&recipient_public_key=0XBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB&value_transferred=0X1234567890ABCDEF&nonce=0X234567890ABCDEF1234567890ABCDEF1&hash=0XDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF&digital_signature=0X1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF

Compile client program:
```
gcc -o client client.c -lsodium
```

Use client program to generate/load public-private key pair:
```
./client
```

Use client program to send a new transaction:
```
./client "0XBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" "0X0000000000000003"
```

Print saved public or private key manually:
```
xxd -p -c 32 public_key.bin
```


[Watch the Screen Recording](https://github.com/simassakenis/digital-currency-v1/blob/main/output.mp4)
