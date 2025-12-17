# Reingegnerizzazione: agent come Deployment + riconciliazione operator-style

## Obiettivo

Portare gli agent (DHCP data-plane) da **Pod singoli** a **Deployment** e adottare un flusso di riconciliazione stile *operator pattern* in cui il controller rende convergente lo stato reale del cluster verso lo stato desiderato derivato dagli oggetti `IPPool`.

Motivazioni principali:

- **Self-healing**: un Deployment garantisce la ricreazione del Pod se viene eliminato o se il nodo muore.
- **Upgrade controllato**: aggiornare l’immagine/PodTemplate via Deployment è un percorso standard Kubernetes.
- **Operatività**: riduce la “fragilità” del Pod ad-hoc, uniforma la gestione lifecycle.

## Modello risultante (IPPool → Agent Deployment)

Per ogni `IPPool` viene mantenuto un **Deployment** in `agentNamespace` (tipicamente `harvester-system`) con:

- `metadata.name`: `util.SafeAgentConcatName(<ippool.namespace>, <ippool.name>)` (stesso naming del vecchio Pod)
- `replicas: 1`
- `spec.template`: equivalente al vecchio `PodSpec` (multus annotation, initContainer ip-setter, container agent, affinity su clusterNetwork, SA dedicata, probes)
- Label chiave (invarianti di relazione):
  - `network.harvesterhci.io/vm-dhcp-controller=agent`
  - `network.harvesterhci.io/ippool-namespace=<ippool.namespace>`
  - `network.harvesterhci.io/ippool-name=<ippool.name>`

Queste label permettono di:

- correlare univocamente agent ↔ ippool
- elencare i Pod del Deployment per determinare readiness
- continuare a usare il watch esistente sui Pod per “triggerare” la riconciliazione.

## Riconciliazione (operator pattern)

### DeployAgent
Implementa la convergenza verso lo stato desiderato:

- risolve `clusterNetwork` dalla NAD associata a `spec.networkName`
- calcola l’immagine desiderata con supporto all’hold upgrade (`hold-ippool-agent-upgrade`)
- **migrazione best-effort**: se `status.agentPodRef` è presente (legacy), prova a cancellare quel Pod e azzera il ref
- crea/aggiorna il Deployment (create se non esiste, update se drift su `spec.template`, `replicas`, strategy)
- salva in `status.agentDeploymentRef` i riferimenti del Deployment (namespace/name/uid/image)

File di riferimento:

- `pkg/controller/ippool/controller.go` (funzione `DeployAgent`)
- `pkg/controller/ippool/common.go` (funzione `prepareAgentDeployment`)

### MonitorAgent
Valuta la salute dell’agent in modo coerente con la semantica “replicas=1”:

- legge il Deployment tramite `status.agentDeploymentRef`
- fallisce se:
  - Deployment non esiste / è in deletion
  - l’immagine del PodTemplate non corrisponde a quella registrata
  - non esiste **esattamente 1** Pod Ready (0 → not ready, >1 → split-brain/deriva)

File di riferimento:

- `pkg/controller/ippool/controller.go` (funzione `MonitorAgent`)

### Cleanup (pause/remove)
In caso di `spec.paused=true` o di rimozione dell’IPPool:

- elimina il Deployment se presente (`status.agentDeploymentRef`)
- elimina eventuale Pod legacy se presente (`status.agentPodRef`)
- azzera cache/IPAM/metriche correlate
- in pause: azzera anche i ref nello `status`.

File di riferimento:

- `pkg/controller/ippool/controller.go` (funzione `cleanup` + logica `OnChange`/`OnRemove`)

## Cambi API / CRD

### API (Go types)

Aggiunto a `IPPoolStatus` il campo:

- `.status.agentDeploymentRef` (tipo `DeploymentReference`)

È stato **mantenuto** `.status.agentPodRef` per compatibilità e migrazione.

File di riferimento:

- `pkg/apis/network.harvesterhci.io/v1alpha1/ippool.go`

### CRD

Aggiornato schema CRD per includere `status.agentDeploymentRef`:

- `chart/crds/network.harvesterhci.io_ippools.yaml`

Nota: il CRD è anche “embedded” nell’eseguibile tramite `pkg/data/data.go` e usato da `pkg/crd/crd.go`.

## Helm / RBAC

Il controller ora necessita permessi per gestire Deployment nel namespace target degli agent.

Aggiornamento:

- `chart/templates/rbac.yaml`: esteso il Role `*-pod-manager` includendo `apiGroups: ["apps"], resources: ["deployments"], verbs: ["get","create","update","patch","delete"]`.

## Test aggiornati

I test della riconciliazione IPPool/agent sono stati riallineati:

- DeployAgent ora valida creazione/upgrade/hold su Deployment
- Migrazione: rimozione Pod legacy quando ancora referenziato
- MonitorAgent ora valida gli errori/ready state sul Deployment e sui Pod selezionati via label

File di riferimento:

- `pkg/controller/ippool/controller_test.go`

## Come proseguire in una nuova sessione

### Dove mettere mano

- Logica reconcile agent: `pkg/controller/ippool/controller.go`
- Template Deployment/Pod: `pkg/controller/ippool/common.go`
- API/CRD: `pkg/apis/network.harvesterhci.io/v1alpha1/ippool.go` + `chart/crds/...`
- RBAC chart: `chart/templates/rbac.yaml`

### Eseguire test / build

In ambienti dove il DNS interno non risolve `proxy.golang.org`, usare:

```bash
GOPROXY=direct GOMAXPROCS=1 go test -p 1 ./...
```

### Rigenerare CRD/controller/clientset

Il flusso standard rimane:

```bash
go generate
```

Questo rigenera:

- i client/controller wrangler
- i CRD YAML in `chart/crds/`
- l’asset embedding in `pkg/data/data.go`

## Note / possibili follow-up

- Valutare una strategia di deprecazione di `status.agentPodRef` una volta completata la migrazione.
- Possibile estensione: watch anche su `Deployment` oltre che sui Pod (oggi il watch sui Pod continua a funzionare perché i Pod del Deployment mantengono le stesse label).
- Ownership: l’ownerReference cross-namespace non è applicabile; la correlazione e garbage-collection avviene tramite label + cleanup su IPPool.
