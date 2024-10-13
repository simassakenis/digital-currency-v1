# digital-currency-v1

This repository is an implementation of a digital payment system from scratch in C. The system consists of a server program that maintains a list of transactions and a client program that sends new transactions. The distribution of money across participants is fully described by the list of transactions at any given time. The current list of transactions can always be accessed at http://localhost:8080.

Each transaction stores the following information:

* Sender public key (32 bytes)
* Recipient public key (32 bytes)
* Value transferred (8 bytes)
* Nonce (16 bytes)
* Hash (32 bytes)
* Digital signature of the hash (64 bytes)
* Last sender transaction index (8 bytes)
* Last recipient transaction index (8 bytes)
* New sender balance (8 bytes)
* New recipient balance (8 bytes)
* Transaction index (8 bytes)

Each participant has a public-private key pair. To send 3 coins to a participant with public key `0X12E369D502D98851D25FAE1C68970B3B5172F7E01F219246ECCFD0E9EE4C9D3D`, the participant simply has to run `./client "0X12E369D502D98851D25FAE1C68970B3B5172F7E01F219246ECCFD0E9EE4C9D3D" "0X0000000000000003"`. Under the hood, the client program looks up the client's own public key, generates a random nonce value, computes a hash of the sender public key, recipient public key, value transferred, and nonce, and then computes a digital signature of the hash using the client's private key. The client program then sends an HTTP request with all these values to the server, which would look like this:

```
http://localhost:8080/?sender_public_key=0X9D6A9DC5D05C429B1DCC164426C654AD7BA77A742277439415641FC18A260FD7&recipient_public_key=0X12E369D502D98851D25FAE1C68970B3B5172F7E01F219246ECCFD0E9EE4C9D3D&value_transferred=0X0000000000000003&nonce=0X356BA90DB4A72109CB17BAEAE81BD31A&hash=0X627332BB0636153F4B956B03FB59977CED27686710DFC3CAD53C22D0315ECCA4&digital_signature=0X0F992749EBF82EF406378CCBEA3F059DFC6AE4A976F70F206A2A8673BCFACB70ACE2CA8C9BEEC0883C6BB2942314212C27DB2040EC466C9647F0829C8F390E07
```

When the server receives this HTTP request for a new transaction, it verifies that the sender has enough balance, that the hash value is correct, and that the digital signature is indeed a signature of the hash given the sender's public key. If all these checks pass, the server program then fills in the last sender transaction index, the last recipient transaction index, the new sender balance, the new recipient balance, and the index of this new transaction in the transaction list, and appends it to the list. This validation logic ensures that only the client could have sent this transaction because no one else would know the private key and be able to generate a valid digital signature. It also prevents an attacker sending the same transaction the second time because the nonce value would make a repeated transaction have a different hash and hence would require a new digital signature.


See [demo.mp4](https://github.com/simassakenis/digital-currency-v1/blob/main/demo.mp4) for an example of how this payment system would be used. I generate public-private key pairs for `bank`, `client1`, and `client2`, send 5 coins from `bank` to `client1`, then 5 coins from `bank` to `client2`, then 3 coins from `client1` to `client2`, and then 10 coins from `client2` to `client1`.

### Usage

There is a dependency on libsodium (for hashing and digital signatures). Follow the installation instructions from https://doc.libsodium.org/installation.

Compile server program:
```
gcc -o server server.c -lsodium
```

Launch server program:
```
./server
```

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
./client "0X12E369D502D98851D25FAE1C68970B3B5172F7E01F219246ECCFD0E9EE4C9D3D" "0X0000000000000003"
```

Print saved public or private key manually:
```
xxd -p -c 32 public_key.bin
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



