```shell
### certificates generation

CA
openssl genrsa -out rootCA.key 2048
openssl genrsa -des3 -out rootCA.key 2048
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.pem

client
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr
openssl x509 -req -in client.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out client.pem -days 500 -sha256

server
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr
openssl x509 -req -in server.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out server.pem -days 500 -sha256

serverCertChain
cat server.pem rootCA.pem client.pem > combo.pem

sample client
curl https://localhost:3000 --cacert rootCA.pem --key client.key  --cert client.pem
```
