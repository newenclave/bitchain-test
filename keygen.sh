openssl ecparam -name secp256k1 -genkey -out ec-priv.pem
openssl ec -in ec-priv.pem -pubout -out ec-pub.pem


