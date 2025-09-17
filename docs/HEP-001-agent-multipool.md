# HEP-001: Unificazione dell'agente DHCP multi-IPPool

**Authors:** vm-dhcp-controller maintainers  
**Status:** Draft  
**Created At:** 2024-03-08  
**Last Updated:** 2024-03-08  

---

## Summary

Proponiamo di sostituire il modello "un pod agente per IPPool" con un unico Deployment di agenti DHCP capace di servire più reti in parallelo. Il controller compone dinamicamente la configurazione (Multus annotation ed env JSON) per ogni IPPool attivo e l'agente avvia watcher e server DHCP per ciascun pool utilizzando un allocatore multi-tenant.

---

## Motivation

L'attuale gestione per-pool genera molti pod, repliche ripetitive della stessa immagine e stato difficile da sincronizzare (argomenti CLI, Multus annotation, lease locali). Aggregare la configurazione lato controller elimina questa duplicazione, consente di riutilizzare un singolo processo con leader election e permette all'allocatore DHCP di mantenere lease isolati per IPPool, allineandosi con l'evoluzione della CRD `IPPool` e dei relativi controller Harvester.

---

## Goals / Non-goals

- *Goals*:  
  - Un Deployment di agenti con interfacce configurate da `AGENT_NETWORK_CONFIGS` e `IPPOOL_REFS_JSON`.  
  - Sincronizzazione dei lease direttamente dallo stato `IPPool.Status.IPv4.Allocated`.  
  - Controller responsabile della Multus annotation e degli env JSON aggiornati.  
  - Allocatore DHCP con gestione delle lease separata per IPPool e cleanup coordinato.
- *Non-goals*:  
  - Supporto IPv6 o cambiamenti all'algoritmo IPAM.  
  - Revisione del webhook o dei controller KubeVirt esistenti oltre agli adattamenti necessari.  
  - Gestione di configurazioni NAD non valide oltre ai controlli attuali (si limita a loggare e saltare pool incompleti).

---

## Proposal / Design

### Componenti modificati

- **Helm chart**: introduce un Deployment dedicato all'agente con capability `NET_ADMIN`, default JSON vuoti e rimozione degli argomenti legacy (`--nic`, `--ippool-ref`, ecc.).【F:chart/templates/agent-deployment.yaml†L1-L59】  
- **Deployment controller**: espone `AGENT_DEPLOYMENT_NAME` e `AGENT_CONTAINER_NAME` via env per guidare le patch runtime.【F:chart/templates/deployment.yaml†L35-L64】  
- **Controller IPPool**: ricompone la Multus annotation, gli env JSON, controlla NAD e aggiorna il Deployment dell'agente ogni volta che cambia l'elenco dei pool attivi.【F:pkg/controller/ippool/controller.go†L247-L452】  
- **Agent runtime**: deserializza le configurazioni per interfacce/IPPool, configura le NIC e avvia watcher per ogni pool attendendo `InitialSyncDone` prima di esporre il servizio DHCP.【F:pkg/agent/agent.go†L37-L317】【F:pkg/agent/ippool/event.go†L33-L189】  
- **Allocatore DHCP**: archivia le lease in `map[ipPoolRef]map[hwAddr]Lease`, fornisce `Run/DryRun` su slice di configurazioni e cleanup condiviso.【F:pkg/dhcp/dhcp.go†L57-L409】【F:pkg/dhcp/dhcp.go†L418-L484】

### Flusso dati/controllo

1. L'IPPool controller etichetta la NAD, aggiorna stato/metrica IPAM e prepara la lista di pool attivi ordinata.【F:pkg/controller/ippool/controller.go†L151-L341】  
2. Il controller serializza `AgentNetConfig` e `IPPoolRefs` in JSON ed aggiorna l'annotation Multus del Deployment agente.【F:pkg/controller/ippool/controller.go†L321-L418】  
3. Il pod agente riceve gli env via Downward API, configura le interfacce (flush, ip addr add, up) e crea un handler per ciascun IPPool osservato.【F:pkg/agent/agent.go†L37-L206】  
4. Ogni handler attende il sync dell'informer e popola l'allocatore DHCP con le lease correnti, segnalando `InitialSyncDone`.【F:pkg/agent/ippool/controller.go†L19-L199】  
5. Dopo il sync, l'agente lancia server DHCP per ogni configurazione con handler per-pool che leggono dal map multi-tenant.【F:pkg/agent/agent.go†L207-L317】【F:pkg/dhcp/dhcp.go†L277-L409】

### Interazioni

- **IPPool CRD**: resta la fonte di verità per CIDR, server/router, esclusioni e lease allocate.【F:pkg/apis/network.harvesterhci.io/v1alpha1/ippool.go†L47-L130】  
- **NAD**: il controller applica label namespace/nome per tracciare l'associazione al pool.【F:pkg/controller/ippool/controller.go†L418-L452】  
- **Management context**: memorizza namespace e factory condivise, necessari per patchare il Deployment agent e registrare i controller.【F:pkg/config/context.go†L63-L173】  
- **Leader election**: sia agent che controller possono disattivarla via flag `--no-leader-election`, altrimenti usano ConfigMap/Lease esistenti.【F:cmd/agent/run.go†L52-L101】【F:cmd/controller/run.go†L38-L110】

### API / manifest / configurazione

- `AgentOptions` estese con i JSON delle configurazioni e riferimenti IPPool.【F:pkg/config/context.go†L45-L64】  
- Deployment agente con env `AGENT_NETWORK_CONFIGS`/`IPPOOL_REFS_JSON`, annotation Multus dinamica e securityContext coerente.【F:chart/templates/agent-deployment.yaml†L21-L59】  
- Controller Deployment con env aggiuntivi per individuare target patch e Downward API `POD_NAMESPACE`.【F:chart/templates/deployment.yaml†L41-L64】

### Distribuzione / orchestrazione

- L'Helm chart crea RBAC dedicato per permettere al controller di patchare il Deployment agente e per far sì che l'agente osservi IPPool/Lease.【F:chart/templates/rbac.yaml†L1-L86】  
- L'agente viene schedulato come ReplicaSet condiviso, così il controller può scalarlo via Helm o orizzontalmente se necessario.【F:chart/templates/agent-deployment.yaml†L1-L59】

---

## Security Considerations

- L'agente necessita di `NET_ADMIN`; il chart garantisce che la capability sia presente anche se l'utente personalizza il securityContext.【F:chart/templates/agent-deployment.yaml†L21-L35】  
- Il controller riceve permessi RBAC per patchare Deployments solo nel proprio namespace, limitando l'impatto di eventuali bug.【F:chart/templates/rbac.yaml†L63-L96】  
- I server DHCP leggono configurazioni dall'IPPool e non aprono porte extra oltre alla 67/UDP sull'interfaccia specifica.【F:pkg/dhcp/dhcp.go†L277-L409】  
- Il fallback su JSON vuoti mantiene l'agente inattivo finché il controller non applica configurazioni valide, evitando esposizione accidentale di interfacce non gestite.【F:cmd/agent/root.go†L51-L102】

---

## Upgrade & Migration Plan

1. Aggiornare il chart: vengono creati il nuovo Deployment agente, RBAC e env aggiuntivi per il controller.【F:chart/templates/deployment.yaml†L35-L79】【F:chart/templates/agent-deployment.yaml†L1-L59】  
2. Una volta che il controller gira con le nuove logiche, ricompone Multus annotation e JSON per ogni IPPool; gli agenti esistenti leggono i valori appena riavviati.  
3. Il vecchio modello per-pool può essere dismesso eliminando eventuali Pod legacy; l'agente condiviso continuerà a servire le lease già presenti grazie alla sincronizzazione iniziale.【F:pkg/agent/ippool/controller.go†L95-L199】  
4. Per rollback è sufficiente ripristinare il chart precedente: il Deployment agente viene rimosso e il controller smette di patchare env/annotation; le risorse IPAM vengono liberate tramite `cleanup`.【F:pkg/controller/ippool/controller.go†L452-L475】

---

## Alternatives Considered

- **Mantenere pod per-pool**: avrebbe richiesto di conservare `prepareAgentPod` e la generazione di Pod dinamici; la logica è stata lasciata commentata come riferimento ma scartata per complessità operativa.【F:pkg/controller/ippool/common.go†L14-L122】  
- **Replica dell'agente via StatefulSet**: non necessario perché l'allocatore non mantiene stato su disco e le lease sono ricostruite da IPPool; un Deployment è sufficiente.  
- **Configurazioni via ConfigMap**: il controller già patcha env/annotation direttamente sul template del Deployment; introdurre ConfigMap avrebbe aggiunto dipendenze di rotazione senza benefici immediati.

---

## Drawbacks / Risks

- Un singolo Deployment rappresenta un single point of failure: crash o rollout errato interrompono il servizio per tutti i pool.【F:pkg/agent/agent.go†L207-L317】  
- Errori di serializzazione JSON lato controller impediscono l'avvio dell'agente; sono presenti log ma non esiste validazione preventiva centralizzata.【F:pkg/controller/ippool/controller.go†L347-L418】  
- Il server DHCP usa `server4.NewServer` per NIC specifiche ma non propaga errori in maniera aggregata; problemi su una sola interfaccia potrebbero passare inosservati.【F:pkg/dhcp/dhcp.go†L318-L409】  
- La sincronizzazione iniziale dipende dal corretto funzionamento degli informer; se fallisce l'agente potrebbe partire con cache incomplete e lease mancanti.【F:pkg/agent/agent.go†L207-L270】

---

## Testing Plan

- Test di riconciliazione controller: verificare Multus annotation, JSON generati e pruning degli argomenti CLI legacy.【F:pkg/controller/ippool/controller.go†L321-L418】  
- Test integrazione agente: simulare più IPPool con informer finti, assicurandosi che `InitialSyncDone` venga rispettato prima dell'avvio DHCP.【F:pkg/agent/ippool/controller.go†L95-L199】  
- Test allocatore DHCP: caricare configurazioni multiple, confermare isolamento `map[ipPoolRef]map[hwAddr]` e corretto cleanup su cancellazione contesto.【F:pkg/dhcp/dhcp.go†L57-L484】  
- E2E: creare IPPool e NAD reali, verificare che l'agente configuri le interfacce (`ip address flush/add/up`) e serva OFFER/ACK coerenti con le lease da CRD.【F:pkg/agent/agent.go†L137-L204】【F:pkg/dhcp/dhcp.go†L277-L372】

---

## Dependencies

- Kubernetes con Multus e CRD Harvester `network.harvesterhci.io/v1alpha1` installate.【F:pkg/controller/ippool/controller.go†L151-L341】【F:pkg/apis/network.harvesterhci.io/v1alpha1/ippool.go†L9-L130】  
- Libreria `insomniacslk/dhcp` per la gestione dei pacchetti DHCPv4 multi-interfaccia.【F:pkg/dhcp/dhcp.go†L11-L15】  
- Client Harvester/KubeVirt generati tramite wrangler già inizializzati nel management context.【F:pkg/config/context.go†L63-L173】

---

## References

- Implementazione controller/agent/dhcp aggiornata nelle ultime 49 commit del repository.【F:pkg/controller/ippool/controller.go†L143-L475】【F:pkg/agent/agent.go†L37-L317】【F:pkg/dhcp/dhcp.go†L57-L484】  
- Helm chart aggiornato per orchestrare il nuovo modello operativo.【F:chart/templates/agent-deployment.yaml†L1-L59】【F:chart/templates/deployment.yaml†L1-L79】【F:chart/templates/rbac.yaml†L1-L132】

---

## Metrics / success criteria

- Tempo di convergenza dell'agente dopo modifiche agli IPPool (<60s).  
- Numero massimo di IPPool gestibili con un singolo pod agente senza perdita di pacchetti DHCP.  
- Assenza di lease orfane dopo cancellazione o pausa di un IPPool (confermata da IPAM e log allocator).

---

