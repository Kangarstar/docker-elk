# Elastic stack (ELK) sur Docker Swarm

[![Elastic Stack version](https://img.shields.io/badge/Elastic%20Stack-9.0.3-00bfb3?style=flat&logo=elastic-stack)](https://www.elastic.co/blog/category/releases)

Ce projet permet de déployer [Elastic stack][elk-stack] en cluster avec Docker et Docker Swarm.

Il vous permettra d'analyser n'importe quel ensemble de données en utilisant les capacités de recherche/agrégation d'Elasticsearch et la puissance de visualisation de Kibana.

Basé sur les  [images Docker officielles][elastic-docker] d' Elastic :

* [Elasticsearch](https://github.com/elastic/elasticsearch/tree/main/distribution/docker)
* [Logstash](https://github.com/elastic/logstash/tree/main/docker)
* [Kibana](https://github.com/elastic/kibana/tree/main/src/dev/build/tasks/os_packages/docker_generator)


---

## tl;dr

```sh
cd /opt
```

```sh
git clone ssh://git@ssh.github.com:443/NTE-Airport-DSI/docker-elk.git
```

```sh
cd /docker-elk
```

```sh
sudo bash elk-setup.sh
```


---

## Sommaire

1. [Prérequis](#prérequis)
   * [Hôte](#hôte)
1. [Exploitation](#exploitation)
   * [Monter le stack](#monter-le-stack)
   * [Setup initial](#setup-initial)
     * [Configuration des utilisateurs](#configuration-des-utilisateurs)
     * [Injection de données](#injection-de-données)
   * [Suppression](#suppression)
   * [Comment réexécuter le stack](#comment-réexécuter-le-stack)
   * [Montée de version](#montée-de-version)
1. [Configuration](#configuration)
   * [Comment configurer Elasticsearch](#comment-configurer-elasticsearch)
   * [Comment configurer Kibana](#comment-configurer-kibana)
   * [Comment configurer Logstash](#comment-configurer-logstash)
   * [Comment régénérer les certificats TLS](#comment-régénérer-les-certificats-tls)
   * [Autre manière de modifier les mots de passe](#autre-manière-de-modifier-les-mots-de-passe)
1. [Mémoire RAM JVM](#mémoire-ram-jvm)
   * [Comment spécifier la quantité de RAM utilisée par un service](#comment-spécifier-la-quantité-de-ram-utilisée-par-un-service)
1. [Approfondir](#approfondir)
   * [Plugins et intégrations](#plugins-et-intégrations)







## Prérequis

### Hôte

* [Docker Engine][docker-install] version **18.06.0** or plus récent
* [Docker Compose][compose-install] version **2.0.0** or plus récent

Par défaut, le stack exposes ces ports:

* 5044: Logstash Beats input
* 50000: Logstash TCP input
* 9600: Logstash monitoring API
* 9200: Elasticsearch HTTP
* 9300: Elasticsearch TCP transport
* 5601: Kibana
* 8220: Fleet-server

## Exploitation

### Monter le stack

Cloner ce repository sur le premier hôte Docker Swarm du cluster. Il va déployer le stack avec les commandes ci-dessous:

```sh
cd /opt
git clone https://github.com/NTE-Airport-DSI/docker-elk.git
```

Ensuite, generer les certificats X.509 pour activer les communications en TLS entre composants:

```sh
$ sudo docker compose up tls -d
```

> [!NOTE]
> Tous les composants Elastic sont configurés pour utiliser les certificats générés par la commande 
> ci-dessus. Pour changer les noms DNS et adresses IP utilisées par les certificats, ou pour les régénérer 
> plus tard, référez vous a la section [Comment régénérer les certificats TLS](#how-to-re-generate-tls-certificates).

Une fois que les certificats TLS sont générés, initialiser le les utilisateurs, groupes et cluster avec cette commande: 

```sh
sudo bash elk-setup.sh
```

Si vous rencontrez un problème avec l'execution du script setup, éxécutez ce script de diagnostic:

```sh
sudo bash elk-diagnostic.sh   
```
  

> [!NOTE]

Accédez à l'interface web Kibana en accédant a <http://localhost:5601> ou <https://kibana.aero44.local:5601> dans votre navigateur puis connectez vous avec vos identifiants.

* user: *elastic*
* password: *****


> [!NOTE]
> Suite a l'initialisation, les utilisateurs ELK `elastic`, `logstash_internal` et `kibana_system` sont créés a partir
> des valeurs définies dans le [`.env`](.env) file (_"changeme"_ par défaut). Le premier est le
> [superutilisateur][builtin-users], les deux autres sont utilisés par Kibana et Logstash pour communiquer avec
> Elasticsearch. Cette action est seulement effectuée pendant l'_initialisation_ du stack. Pour changer les mots de passe
> _après_ l'initialisation, référez vous a la prochaine section.

### Setup initial

#### Configuration des utilisateurs

> [!NOTE]

Le mot de passe _"changeme"_ qui est défini par défaut pour tous les utilisateurs mentionné est **non sécurisé**. Pour sécuriser le stack, il est recommandé de changer les mots de passe des utilisateurs Elasticsearch.

1. Reset des mots de passe des utilisateurs par défaut

    Ces commandes changent le mot de passe des comptes `elastic`, `logstash_internal` and `kibana_system` users.

    ```sh
    docker compose exec elasticsearch bin/elasticsearch-reset-password --batch --user elastic --url https://localhost:9200
    ```

    ```sh
    docker compose exec elasticsearch bin/elasticsearch-reset-password --batch --user logstash_internal --url https://localhost:9200
    ```

    ```sh
    docker compose exec elasticsearch bin/elasticsearch-reset-password --batch --user kibana_system --url https://localhost:9200
    ```

    Pour les comptes de [monitoring][ls-monitoring] interne via Beats la même operation est valide pour tous les 
    [comptes][builtin-users] internes.

1. Reset des mots de passe dans les fichiers de configuration
    Remplacez le mot de passe de l'utilisateur `elastic` dans le fichier `.env` par le mot de passe généré à l'étape précédente.

    Remplacez le mot de passe de l'utilisateur `logstash_internal` dans le fichier .`.env` par le mot de passe généré à l'étape précédente.
   Cette valeur est référencée dans le fichier de pipeline Logstash (`logstash/pipeline/logstash.conf`).

    Remplacez le mot de passe de l'utilisateur `kibana_system` dans le fichier `.env` par le mot de passe généré à l'étape précédente.
    Cette valeur est référencée dans le fichier de configuration de Kibana (`kibana/config/kibana.yml`).

    Consultez la section [Configuration](#configuration) ci-dessous pour plus d'informations sur ces fichiers de configuration.

1. Redémarrer le(s) service(s) et connectez vous avec le(s) nouveau mot de passe 

    ```sh
    docker service update --force elk_kibana
    ```

> [!NOTE]
> Documentation sécurité ELK : [Sécuriser son Elastic Stack][sec-cluster].

#### Injection de données

Connectez vous a l'interface Kibana <https://localhost:5601> ou <https://kibana.aero44.local:5601> depuis votre navigateur 
avec les identifiants configurés et stockés dans le Keepass

Une fois le stack entièrement configuré, il est possible d'ingérer des logs.

La configuration Logstash actuelle permet d'envoyer des données au port TCP 50000. Pour un envoi simple de logs, vous pouvez utiliser 
les commandes suivantes selon la version de `nc` (Netcat) installée — par exemple pour remonter le log 
`/path/to/logfile.log` dans Elasticsearch via Logstash, exécutez:

```sh
# Executez `nc -h` pour déterminer la version de `nc` 

cat /path/to/logfile.log | nc -q0 localhost 50000          # BSD
cat /path/to/logfile.log | nc -c localhost 50000           # GNU
cat /path/to/logfile.log | nc --send-only localhost 50000  # nmap
```


### Suppression

Les données Elasticsearch sont stockées dans des volumes docker. Par défaut, l'execution du script `elk-rm.sh` va eteindre les conteneurs sans supprimer de données:

```sh
cd /opt/docker-elk
sudo bash elk-rm.sh
```

### Comment réexécuter le stack

Pour relancer le stack et prendre en compte les modifications de configuration (certificats, mots de passe, fichier de configuration ELK)  
Vous pouvez simplement réexecuter le script de setup:

```sh
sudo bash elk-setup.sh
```

Pour supprimer les volumes, il est recommandé d'utiliser la section `Volumes` de la console `portainer` accessible depuis <https://portainer.aero44.local:9443/>

### Montée de Version

Pour changer la version du stack, il est possible de modifier la valeur `ELASTIC_VERSION` dans le fichier [`.env`](.env)

> [!IMPORTANT]
> Toujours suivre les [recommendations de montée de version officielles][upgrade] for pour chaque composant individuel
> avant de mettre a jour le stack.

## Configuration

> [!IMPORTANT]
> Les configurations ne sont pas rechargées automatiquement, il faut redémarrer chaque > composant individuel après toute modification de la configuration.

### Comment configurer Elasticsearch

La configuration d'Elasticsearch est stockée dans [`elasticsearch/config/elasticsearch.yml`][config-es].

Il est possible d'override les variables d'Elasticsearch en spécifiant des variables dans le Docker Stack:

```yml
elasticsearch:

  environment:
    network.host: _non_loopback_
    cluster.name: my-cluster
```
Référez vous a la documentation pour plus d'explication sur la configuration d' [Elasticsearch sous Docker][es-docker].

### Comment configurer Kibana

La configuration de Kibana est stockée dans [`kibana/config/kibana.yml`][config-kbn].

Il est possible d'override les variables de Kibana en spécifiant des variables dans le Docker Stack:

```yml
kibana:

  environment:
    SERVER_NAME: kibana.example.org
```

Référez vous a la documentation pour plus d'explication sur la configuration de [Kibana sous Docker][kbn-docker].

### Comment configurer Logstash

La configuration de Logstash est stockée dans [`logstash/config/logstash.yml`][config-ls].

Il est possible d'override les variables de Logstash en spécifiant des variables dans le Docker Stack:

```yml
logstash:

  environment:
    LOG_LEVEL: debug
```

Référez vous a la documentation pour plus d'explication sur la configuration de [Logstash sous Docker][ls-docker].

### Comment régénérer les certificats TLS

Pour régénérer les certificats TLS et clefs privées, vérifiez que le fichier [tls/instances.yml](./tls/instances.yml) contient une liste des certificats avec domaines appropriés ainsi que les adresses IP de votre environnement.

Ensuite, supprimez les certificats TLS et clefs privées avec cette commande:

```console
$ find tls/certs -name ca -prune -or -type d -mindepth 1 -exec rm -rfv {} +
tls/certs/kibana/kibana.key
tls/certs/kibana/kibana.crt
tls/certs/kibana
tls/certs/fleet-server/fleet-server.key
tls/certs/fleet-server/fleet-server.crt
tls/certs/fleet-server
tls/certs/elasticsearch/elasticsearch.key
tls/certs/elasticsearch/elasticsearch.crt
tls/certs/elasticsearch
```

et relancez la commmande:

```sh
$ sudo docker compose up tls -d
```

### Autre manière de modifier les mots de passe

Si le changement de mot de passe n'est pas possible avec les méthodes mentionnées précedemment (dont les [built-in users][builtin-users]), vous pouvez utiliser l'API d'Elasticsearch.

Par exemple pour l'utilisateur `elastic` (modifier "/user/elastic" dans l'URL avec l'utilisateur souhaité):

```sh
curl -XPOST -D- 'https://localhost:9200/_security/user/elastic/_password' \
    --cacert tls/certs/ca/ca.crt \
    -H 'Content-Type: application/json' \
    -u elastic:<your current elastic password> \
    -d '{"password" : "<your new password>"}'
```

## Mémoire RAM JVM

### Comment spécifier la quantité de RAM utilisée par un service

La quantité de RAM des conteneurs Logstash et Elasticsearch est régie par les variables d'environnement JVM définies dans le `docker-stack.yml`. 

| Service       | Variable d'environnement |
|---------------|--------------------------|
| Elasticsearch | ES_JAVA_OPTS             |
| Logstash      | LS_JAVA_OPTS             |

Pour redimensionner la configuration JVM par défaut, modifiez les variables d'environnement dans le fichier `docker-stack.yml`.

Par exemple, pour configurer la mémoire Heap JVM maximale a 1GB pour Logstash:

```yml
logstash:

  environment:
    LS_JAVA_OPTS: -Xms1g -Xmx1g
```

Lorsque les variables JVM ne sont pas attribuées:

* Elasticsearch [détermine automatiquement][es-heap] la mémoire Heap JVM.
* Logstash a une mémoire Heap JVM fixe de 1GB.

## Approfondir

### Plugins et intégrations

Consultez les pages wiki suivantes:

* [Applications externes](https://github.com/deviantony/docker-elk/wiki/External-applications)
* [Integrations populaires](https://github.com/deviantony/docker-elk/wiki/Popular-integrations)

[elk-stack]: https://www.elastic.co/what-is/elk-stack
[elastic-docker]: https://www.docker.elastic.co/
[subscriptions]: https://www.elastic.co/subscriptions
[es-security]: https://www.elastic.co/guide/en/elasticsearch/reference/current/security-settings.html
[license-settings]: https://www.elastic.co/guide/en/elasticsearch/reference/current/license-settings.html
[license-mngmt]: https://www.elastic.co/guide/en/kibana/current/managing-licenses.html
[license-apis]: https://www.elastic.co/guide/en/elasticsearch/reference/current/licensing-apis.html

[elastdocker]: https://github.com/sherifabdlnaby/elastdocker

[docker-install]: https://docs.docker.com/get-docker/
[compose-install]: https://docs.docker.com/compose/install/
[linux-postinstall]: https://docs.docker.com/engine/install/linux-postinstall/

[bootstrap-checks]: https://www.elastic.co/guide/en/elasticsearch/reference/current/bootstrap-checks.html
[es-sys-config]: https://www.elastic.co/guide/en/elasticsearch/reference/current/system-config.html
[es-heap]: https://www.elastic.co/guide/en/elasticsearch/reference/current/important-settings.html#heap-size-settings

[win-filesharing]: https://docs.docker.com/desktop/settings/windows/#file-sharing
[mac-filesharing]: https://docs.docker.com/desktop/settings/mac/#file-sharing

[builtin-users]: https://www.elastic.co/guide/en/elasticsearch/reference/current/built-in-users.html
[es-tls]: https://www.elastic.co/guide/en/elasticsearch/reference/current/manually-configure-security.html
[ls-monitoring]: https://www.elastic.co/guide/en/logstash/current/monitoring-with-metricbeat.html
[sec-cluster]: https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-cluster.html

[connect-kibana]: https://www.elastic.co/guide/en/kibana/current/connect-to-elasticsearch.html
[index-pattern]: https://www.elastic.co/guide/en/kibana/current/index-patterns.html

[config-es]: ./elasticsearch/config/elasticsearch.yml
[config-kbn]: ./kibana/config/kibana.yml
[config-ls]: ./logstash/config/logstash.yml

[es-docker]: https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html
[kbn-docker]: https://www.elastic.co/guide/en/kibana/current/docker.html
[ls-docker]: https://www.elastic.co/guide/en/logstash/current/docker-config.html

[upgrade]: https://www.elastic.co/guide/en/elasticsearch/reference/current/setup-upgrade.html

<!-- markdownlint-configure-file
{
  "MD033": {
    "allowed_elements": [ "picture", "source", "img" ]
  }
}
-->
