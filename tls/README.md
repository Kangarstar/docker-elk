# Certificats TLS

Ce dossier stocke les certificats X.509 ainsi que les clefs privées utilisées pour chiffrer les communications entre composants Elastic avec TLS.

Ils peuvent être générés avec la commande `docker compose up tls`, qui va créer une arborescence similaire a celle ci dessous contenant les certificats et clefs.
(selon le contenu du fichier [instances.yml](./instances.yml)):

```tree
certs
│    
├── ca
│   ├── ca.crt
│   └── ca.key
├── elasticsearch
│   ├── elasticsearch.crt
│   └── elasticsearch.key
├── fleet-server
│   ├── fleet-server.crt
│   └── fleet-server.key
└── kibana
    ├── kibana.crt
    └── kibana.key
```
