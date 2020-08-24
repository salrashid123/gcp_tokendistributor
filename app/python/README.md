## Python TokenClient

TODO: python grpcClient


### Build 
```bash
virtualenv env --python=/usr/bin/python3.7
source env/bin/activate
pip install grpcio-tools  protobuf proto-plus google.api.core
python -m grpc_tools.protoc --proto_path=.  -I . --python_out=.  --grpc_python_out=. tokenservice.proto
```

### Deploy

TODO: Dockerfile

TODO: GCP Secrets manager, flags
