#on CA
openssl genrsa -out ca.key.pem 4096
openssl req -x509 -new -sha256 -days 3650 \
  -key ca.key.pem -out ca.cert.pem \
  -subj "/C=GB/ST=London/L=London/O=M4 CA/CN=M4 CA"

#on client
openssl genrsa -out client.key.pem 2048
openssl req -new -key client.key.pem -out client.csr.pem \
  -subj "/C=GB/ST=London/L=London/O=M4 Client/CN=m4.com"

#transfer csr to ca
openssl x509 -req -in client.csr.pem \
  -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial \
  -out client.cert.pem -days 825 -sha256

cat client.cert.pem ca.cert.pem > client.fullchain.pem

#on client docker-compose nginx
services:
  nginx:
    image: nginx:stable
    container_name: m4-nginx
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./client.fullchain.pem:/etc/nginx/certs/client.fullchain.pem:ro
      - ./client.key.pem:/etc/nginx/certs/client.key.pem:ro

#create local DNS record for m4.com
#test tls connection
curl --cacert ca.cert.pem https://m4.com -v
