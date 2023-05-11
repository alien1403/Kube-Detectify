# Introducere
**Kube-Detectify** este un sistem de analiza a Audit Log-urilor generate intr-un cluster de Kubernetes
si de detectie a unui set de atacuri efectuate asupra cluster-ului respectiv de catre un atacator local.

Sistemul este proiectat ca un web server Flask, catre care cluster-ul face cereri de tip *POST* in timp
real, pe masura ce sunt generate log-urile corespunzatoare operatiilor efectuate asupra sa. Obiectele
JSON sunt apoi procesate prin apelul unor functii specifice fiecarui tip de atac, definite in fisiere
distincte. In cazul in care sunt detectate operatii malitioase, acestea vor fi simultan salvate local in
directorul '*Log Storage*' si afisate in consola din front-end.

Cele 3 tipuri de atacuri care pot fi detectate sunt enumerate mai jos, impreuna cu cate o sursa unde sunt
accesibile informatii suplimentare:
- [Container Administration Command Abuse](https://attack.mitre.org/techniques/T1609/)
- [Container Deployment](https://attack.mitre.org/techniques/T1610/)
- [Internal Image Implanting](https://attack.mitre.org/techniques/T1525/)




# Utilizare si Configurare
## Audit Logging si functia de Webhook

***Instructiunile urmatoare au fost testate numai intr-un cluster de Minikube v1.26.1 hostat local, 
folosind Flask v2.2 pe Ubuntu 18.04.3 LTS***
  
Pentru configurarea functiei de Audit Logging trebuie realizata conectarea la un Master Node, resursele
necesare fiind accesibile in directorul '*Kubernetes Config Files*'. In root-ul sistemului de fisiere
din Master Node ('/') vom crea folderul "kube/Audit Logs", in interiorul caruia vom adauga fisierele 
"policy.yaml" si "webhook.yaml". 

In interiorul fisierului 'webhook.yaml' se regaseste secventa 'server: http://10.17.72.12:8080/postLogs',
care trebuie inlocuita potrivit urmatorului format:
```
server: <protocol>/<ip>/:<port>/postLogs
```
Aici, \<ip> reprezinta ip-ul web server-ului catre care se vor trimite log-urile, iar \<port> reprezinta
portul pe care ruleaza server-ul. In interiorul directorului '/etc/kubernetes/manifests/' se gaseste
fisierul 'kube-apiserver.yaml' care va trebui inlocuit cu fisierul 'kube-apiserver.yaml' din directorul
"Kubernetes Config Files".

## Web Server

Dupa clonarea repo-ului, in acelasi director trebuie creat un *python environment* in care va fi instalat
modulul 'flask'. Aplicatia propriu-zisa este scrisa in fisierul "KubeDetectify.py", iar pentru a-i indica
server-ului de flask fisierul respectiv, trebuie declarata o variabila de mediu cu ajutorul comenzii:
```
export FLASK_APP=KubeDetectify.py
```
Serverul de Flask va fi pornit prin intermediul comenzii: 
```
flask run -h <ip> -p <port>
```
Cele doua campuri trebuie inlocuite cu aceleasi valori ca cele de mai sus.

## Navigarea in browser

Pagina principala este accesibila la adresa '\<ip>:\<port>', de unde utilizatorul poate naviga catre cele 3 
console, corespunzatoare celor 3 tipuri de atacuri. Script-urile sunt executate automat in momentul in care
server-ul primeste log-urile de la cluster, iar o avertizare asupra fiecarui posibil atac interceptat va fi
vizbila in consola corespunzatoare dupa o reimprospatare a paginii.
